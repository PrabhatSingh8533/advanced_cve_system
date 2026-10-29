"""
CVE Time Series Analysis Module.

Provides:
- Trend decomposition (trend + seasonality + residual)
- Year-over-year growth analysis
- Rolling statistics
- Anomaly detection
- ARIMA forecasting
"""

import warnings
import numpy as np
import pandas as pd
from loguru import logger

warnings.filterwarnings("ignore")


class CVETimeSeriesAnalyzer:
    """
    Analyzes CVE time series data for trends and patterns.
    """

    def __init__(self):
        logger.info("CVETimeSeriesAnalyzer initialized")

    def compute_rolling_stats(
        self,
        df: pd.DataFrame,
        value_col: str = "total_cves",
        windows: list = [3, 6, 12]
    ) -> pd.DataFrame:
        """
        Compute rolling mean and std for multiple windows.

        Args:
            df: DataFrame with date index
            value_col: Column to analyze
            windows: Rolling window sizes (months)

        Returns:
            DataFrame with rolling statistics added
        """
        result = df.copy()

        for window in windows:
            result[f"rolling_mean_{window}m"] = (
                result[value_col]
                .rolling(window=window, min_periods=1)
                .mean()
                .round(1)
            )
            result[f"rolling_std_{window}m"] = (
                result[value_col]
                .rolling(window=window, min_periods=1)
                .std()
                .round(1)
            )

        logger.info(f"Rolling stats computed: windows={windows}")
        return result

    def year_over_year_growth(
        self,
        df: pd.DataFrame,
        value_col: str = "total_cves"
    ) -> pd.DataFrame:
        """
        Calculate year-over-year growth rates.

        Returns:
            DataFrame with YoY growth percentages
        """
        yearly = (
            df.groupby("year")[value_col]
            .sum()
            .reset_index()
        )
        yearly.columns = ["year", "total"]
        yearly["prev_year"] = yearly["total"].shift(1)
        yearly["yoy_growth"] = (
            (yearly["total"] - yearly["prev_year"])
            / yearly["prev_year"] * 100
        ).round(2)
        yearly["yoy_change"] = (
            yearly["total"] - yearly["prev_year"]
        ).fillna(0).astype(int)

        logger.info("YoY growth calculated")
        return yearly

    def detect_anomalies(
        self,
        df: pd.DataFrame,
        value_col: str = "total_cves",
        threshold: float = 2.5
    ) -> pd.DataFrame:
        """
        Detect anomalous months using Z-score method.

        Args:
            threshold: Z-score threshold for anomaly

        Returns:
            DataFrame with anomaly flags
        """
        result = df.copy()
        values = result[value_col]
        mean = values.mean()
        std = values.std()

        result["z_score"] = ((values - mean) / std).round(3)
        result["is_anomaly"] = result["z_score"].abs() > threshold
        result["anomaly_direction"] = np.where(
            result["z_score"] > threshold, "spike",
            np.where(result["z_score"] < -threshold, "dip", "normal")
        )

        anomalies = result[result["is_anomaly"]].shape[0]
        logger.info(f"Anomaly detection: {anomalies} anomalies found")
        return result

    def decompose_trend(
        self,
        df: pd.DataFrame,
        value_col: str = "total_cves",
        period: int = 12
    ) -> dict:
        """
        Decompose time series into trend + seasonal + residual.

        Returns:
            Dict with decomposition components
        """
        try:
            from statsmodels.tsa.seasonal import seasonal_decompose

            series = df[value_col].values.astype(float)

            if len(series) < period * 2:
                logger.warning("Not enough data for decomposition")
                return {}

            result = seasonal_decompose(
                series,
                model="additive",
                period=period,
                extrapolate_trend="freq"
            )

            return {
                "trend": result.trend.tolist(),
                "seasonal": result.seasonal.tolist(),
                "residual": result.resid.tolist(),
                "observed": result.observed.tolist(),
            }

        except Exception as e:
            logger.error(f"Decomposition error: {e}")
            return {}

    def compute_severity_trends(
        self,
        df: pd.DataFrame
    ) -> dict:
        """
        Analyze severity distribution trends over time.

        Returns:
            Dict with severity trends by year
        """
        severity_cols = [
            c for c in df.columns
            if c.startswith("sev_")
        ]

        if not severity_cols:
            return {}

        yearly_severity = (
            df.groupby("year")[severity_cols]
            .sum()
            .reset_index()
        )

        # Calculate percentages
        total_col = "total_cves"
        if total_col in df.columns:
            yearly_total = df.groupby("year")[total_col].sum()
            for col in severity_cols:
                sev_name = col.replace("sev_", "pct_")
                yearly_severity[sev_name] = (
                    yearly_severity[col]
                    / yearly_total.values * 100
                ).round(2)

        result = {}
        for _, row in yearly_severity.iterrows():
            result[int(row["year"])] = row.to_dict()

        return result

    def compute_exploit_trends(
        self,
        df: pd.DataFrame
    ) -> dict:
        """Analyze exploit type distribution trends."""
        exploit_cols = [
            c for c in df.columns
            if c.startswith("exploit_")
        ]

        if not exploit_cols:
            return {}

        yearly = (
            df.groupby("year")[exploit_cols]
            .sum()
            .reset_index()
        )

        result = {}
        for _, row in yearly.iterrows():
            result[int(row["year"])] = {
                col.replace("exploit_", "").replace("_", " ").title(): int(val)
                for col, val in row.items()
                if col.startswith("exploit_")
            }

        return result

    def get_summary_stats(
        self, df: pd.DataFrame
    ) -> dict:
        """Get summary statistics for the dataset."""
        total_col = "total_cves"
        if total_col not in df.columns:
            return {}

        return {
            "total_cves": int(df[total_col].sum()),
            "date_range": {
                "start": str(df["date"].min().date()),
                "end": str(df["date"].max().date()),
            },
            "monthly_avg": round(float(df[total_col].mean()), 1),
            "monthly_max": int(df[total_col].max()),
            "monthly_min": int(df[total_col].min()),
            "total_months": len(df),
            "years_covered": sorted(df["year"].unique().tolist()),
        }
