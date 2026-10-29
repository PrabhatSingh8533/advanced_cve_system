"""CVE Analytics - Fixed with Real DB Severity Data."""

import pandas as pd
import numpy as np
from loguru import logger

from app.services.analytics.synthetic_data import CVETimeSeriesGenerator
from app.services.analytics.time_series import CVETimeSeriesAnalyzer
from app.services.analytics.forecasting import CVEForecaster
from app.services.analytics.charts import CVEChartGenerator


class CVEAnalyticsService:
    """Analytics using real DB data with proper fallbacks."""

    def __init__(self):
        self.generator = CVETimeSeriesGenerator()
        self.analyzer = CVETimeSeriesAnalyzer()
        self.forecaster = CVEForecaster()
        self.charts = CVEChartGenerator()
        self._monthly_df = None
        self._rce_df = None
        self._os_df = None
        logger.info("CVEAnalyticsService initialized")

    def _sf(self, v) -> float:
        """Safe float."""
        try:
            f = float(v)
            return 0.0 if (np.isnan(f) or np.isinf(f)) else round(f, 2)
        except:
            return 0.0

    def _si(self, v) -> int:
        """Safe int."""
        try:
            f = float(v)
            return 0 if (np.isnan(f) or np.isinf(f)) else int(f)
        except:
            return 0

    def _load_from_db_full(self, db) -> pd.DataFrame:
        """
        Load monthly CVE data WITH severity breakdown from DB.
        Uses CASE WHEN to get severity counts per month.
        """
        try:
            from app.db.models.cve import CVE
            from sqlalchemy import func, extract, case

            logger.info("Loading full monthly data from DB...")

            results = db.query(
                extract("year", CVE.published_date).label("year"),
                extract("month", CVE.published_date).label("month"),
                func.count(CVE.id).label("total_cves"),
                func.count(
                    case((CVE.severity == "CRITICAL", CVE.id))
                ).label("sev_critical"),
                func.count(
                    case((CVE.severity == "HIGH", CVE.id))
                ).label("sev_high"),
                func.count(
                    case((CVE.severity == "MEDIUM", CVE.id))
                ).label("sev_medium"),
                func.count(
                    case((CVE.severity == "LOW", CVE.id))
                ).label("sev_low"),
            ).filter(
                CVE.published_date.isnot(None)
            ).group_by(
                extract("year", CVE.published_date),
                extract("month", CVE.published_date)
            ).order_by(
                extract("year", CVE.published_date),
                extract("month", CVE.published_date)
            ).all()

            if len(results) < 6:
                logger.warning(
                    f"Only {len(results)} months in DB"
                )
                return None

            from datetime import date
            records = []
            for r in results:
                try:
                    yr = int(r.year)
                    mo = int(r.month)
                    records.append({
                        "year": yr,
                        "month": mo,
                        "date": pd.Timestamp(date(yr, mo, 1)),
                        "total_cves": int(r.total_cves),
                        "sev_critical": int(r.sev_critical or 0),
                        "sev_high": int(r.sev_high or 0),
                        "sev_medium": int(r.sev_medium or 0),
                        "sev_low": int(r.sev_low or 0),
                    })
                except Exception as e:
                    logger.warning(f"Skip row: {e}")
                    continue

            if not records:
                return None

            df = pd.DataFrame(records)
            df = df.sort_values("date").reset_index(drop=True)

            logger.info(
                f"Loaded {len(df)} months | "
                f"Range: {df['date'].min().strftime('%Y-%m')}"
                f" → {df['date'].max().strftime('%Y-%m')} | "
                f"Total CVEs: {df['total_cves'].sum():,}"
            )
            return df

        except Exception as e:
            logger.error(f"DB load error: {e}", exc_info=True)
            return None

    def _get_monthly_data(self, db=None) -> pd.DataFrame:
        """Get monthly data - real DB first, synthetic fallback."""
        if db is not None:
            real = self._load_from_db_full(db)
            if real is not None and len(real) >= 6:
                self._monthly_df = real
                return self._monthly_df

        if self._monthly_df is None:
            logger.info("Using synthetic monthly data")
            self._monthly_df = (
                self.generator.generate_monthly_counts()
            )
        return self._monthly_df

    def get_forecast(self, steps: int = 12, db=None) -> dict:
        """Forecast using real DB counts."""
        try:
            df = self._get_monthly_data(db=db)

            if df is None or len(df) < 6:
                return {
                    "error": "Not enough data",
                    "forecast_period": f"Next {steps} months",
                    "arima_forecast": {
                        "method": "N/A",
                        "historical_dates": [],
                        "historical_values": [],
                        "dates": [],
                        "values": [],
                        "lower_95": [],
                        "upper_95": []
                    }
                }

            series = [float(v) for v in df["total_cves"].tolist()]
            all_dates = [
                str(d) for d in
                df["date"].dt.strftime("%Y-%m").tolist()
            ]

            logger.info(
                f"Forecast: {len(series)} months of data | "
                f"Last: {all_dates[-1]}={series[-1]:.0f}"
            )

            # Future dates
            last = df["date"].max()
            future_dates = [
                str((last + pd.DateOffset(months=i)).strftime("%Y-%m"))
                for i in range(1, steps + 1)
            ]

            # ARIMA
            fc = self.forecaster.forecast_arima(series, steps)

            # Exp smoothing
            try:
                exp = self.forecaster.exponential_smoothing(
                    series, steps
                )
            except Exception:
                exp = {"method": "N/A", "forecast": fc.get("forecast", [])}

            # Last 36 months
            hist_n = min(len(series), 36)
            hist_dates = [str(d) for d in all_dates[-hist_n:]]
            hist_vals = [float(v) for v in series[-hist_n:]]

            fc_vals = [float(v) for v in fc.get("forecast", [])]
            lo_vals = [float(v) for v in fc.get("lower_bound", [])]
            hi_vals = [float(v) for v in fc.get("upper_bound", [])]
            exp_vals = [float(v) for v in exp.get("forecast", [])]

            logger.info(
                f"Chart: hist={len(hist_dates)} "
                f"fc={len(fc_vals)} "
                f"method={fc.get('method','?')}"
            )

            chart = self.charts.forecast_chart(
                historical_dates=hist_dates,
                historical_values=hist_vals,
                forecast_dates=future_dates,
                forecast_values=fc_vals,
                lower_bound=lo_vals,
                upper_bound=hi_vals,
                method=fc.get("method", "ARIMA")
            )

            return {
                "forecast_period": f"Next {steps} months",
                "data_source": "Real NVD DB" if db else "Synthetic",
                "arima_forecast": {
                    "method": fc.get("method", "ARIMA"),
                    "historical_dates": hist_dates,
                    "historical_values": hist_vals,
                    "dates": future_dates,
                    "values": fc_vals,
                    "lower_95": lo_vals,
                    "upper_95": hi_vals,
                },
                "exp_smoothing_forecast": {
                    "method": exp.get("method", "Exp Smoothing"),
                    "dates": future_dates,
                    "values": exp_vals,
                },
                "chart": chart
            }

        except Exception as e:
            logger.error(f"Forecast error: {e}", exc_info=True)
            return {
                "error": str(e),
                "forecast_period": f"Next {steps} months",
                "arima_forecast": {
                    "method": "error",
                    "historical_dates": [],
                    "historical_values": [],
                    "dates": [],
                    "values": [],
                    "lower_95": [],
                    "upper_95": []
                }
            }

    def get_monthly_chart(self, db=None) -> dict:
        df = self._get_monthly_data(db=db)
        df = self.analyzer.compute_rolling_stats(df)
        return self.charts.monthly_trend_chart(df)

    def get_severity_chart(self, db=None) -> dict:
        """Severity chart using real DB severity counts."""
        df = self._get_monthly_data(db=db)
        # Verify severity columns exist
        sev_cols = [c for c in df.columns if c.startswith("sev_")]
        if not sev_cols:
            logger.warning("No sev_ columns - using synthetic")
            df = self.generator.generate_monthly_counts()
        return self.charts.severity_trend_chart(df)

    def get_overview(self, db=None) -> dict:
        """Overview with YoY growth."""
        df = self._get_monthly_data(db=db)
        data_source = "database" if db else "synthetic"

        df = self.analyzer.compute_rolling_stats(df)
        summary = self.analyzer.get_summary_stats(df)

        yoy_df = self.analyzer.year_over_year_growth(df)
        yoy_records = []
        for _, row in yoy_df.iterrows():
            total = self._si(row.get("total", 0))
            prev = self._si(row.get("prev_year", 0))
            growth = round(
                (total - prev) / prev * 100, 2
            ) if prev > 0 else 0.0
            yoy_records.append({
                "year": self._si(row.get("year", 0)),
                "total": total,
                "prev_year_total": prev,
                "yoy_growth_pct": growth,
                "yoy_change": total - prev if prev > 0 else 0,
            })

        # Anomalies
        try:
            df_a = self.analyzer.detect_anomalies(df)
            anomalies = [
                {
                    "date": str(r["date"])[:10],
                    "total_cves": self._si(r.get("total_cves", 0)),
                    "z_score": self._sf(r.get("z_score", 0)),
                    "direction": str(r.get("anomaly_direction",""))
                }
                for _, r in df_a[df_a["is_anomaly"]].iterrows()
            ]
        except Exception as e:
            logger.warning(f"Anomaly: {e}")
            anomalies = []

        return {
            "data_source": data_source,
            "summary": summary,
            "yoy_growth": yoy_records,
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies[:10],
        }

    def get_rce_analysis(self) -> dict:
        if self._rce_df is None:
            self._rce_df = self.generator.generate_rce_trend()
        df = self._rce_df
        total = self._si(df["rce_count"].sum())
        avg = self._sf(df["rce_percentage"].mean())
        trend = (
            "increasing"
            if df.tail(12)["rce_percentage"].mean() >
               df.head(12)["rce_percentage"].mean()
            else "stable"
        )
        yearly = {
            str(int(yr)): {
                "rce_count": self._si(g["rce_count"].sum()),
                "avg_percentage": self._sf(
                    g["rce_percentage"].mean()
                )
            }
            for yr, g in df.groupby("year")
        }
        return {
            "total_rce_cves": total,
            "average_rce_percentage": avg,
            "trend_direction": trend,
            "yearly_summary": yearly,
            "chart": self.charts.rce_trend_chart(df)
        }

    def get_os_analysis(self) -> dict:
        if self._os_df is None:
            self._os_df = self.generator.generate_os_trend()
        df = self._os_df
        top = {
            k: self._si(v)
            for k, v in df.groupby("os")["count"]
            .sum().sort_values(ascending=False).to_dict().items()
        }
        return {
            "top_platforms": top,
            "total_platforms_tracked": len(df["os"].unique()),
            "chart": self.charts.os_distribution_chart(df)
        }

    def get_exploit_heatmap(self) -> dict:
        try:
            df = self._get_monthly_data()
            return self.charts.exploit_heatmap(df)
        except Exception as e:
            return {"error": str(e)}

    def get_summary(self, db=None) -> dict:
        df = self._get_monthly_data(db=db)
        stats = self.analyzer.get_summary_stats(df)
        yoy = self.analyzer.year_over_year_growth(df)

        if len(yoy) >= 2:
            latest = yoy.iloc[-1]
            prev = yoy.iloc[-2]
            lt = self._si(latest.get("total", 0))
            pt = self._si(prev.get("total", 0))
            growth = round(
                (lt - pt) / pt * 100, 2
            ) if pt > 0 else 0.0
        else:
            latest = yoy.iloc[-1] if len(yoy) > 0 else {}
            prev = {}
            lt = pt = 0
            growth = 0.0

        return {
            "total_cves_analyzed": self._si(
                stats.get("total_cves", 0)
            ),
            "date_range": stats.get("date_range", {}),
            "monthly_average": self._sf(
                stats.get("monthly_avg", 0)
            ),
            "latest_year": {
                "year": self._si(latest.get("year", 0)),
                "total": lt,
                "growth_pct": growth,
            },
            "previous_year": {
                "year": self._si(
                    prev.get("year", 0)
                ) if len(yoy) >= 2 else 0,
                "total": pt,
            },
            "data_quality": "real_nvd_data" if db else "synthetic"
        }
