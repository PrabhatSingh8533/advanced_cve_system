"""CVE Trend Forecasting - Fully Fixed Version."""

import warnings
import numpy as np
import pandas as pd
from loguru import logger

warnings.filterwarnings("ignore")


class CVEForecaster:
    """Forecasts future CVE counts - robust implementation."""

    def __init__(self):
        logger.info("CVEForecaster initialized")

    def fit_arima(
        self, series: list, order: tuple = (1, 1, 1)
    ) -> dict:
        """Fit ARIMA model with full error handling."""
        try:
            from statsmodels.tsa.arima.model import ARIMA

            data = np.array(series, dtype=float)

            if len(data) < 10:
                return {"success": False, "error": "Too few points"}

            # Fix NaN and Inf
            data = pd.Series(data).ffill().bfill().values
            if np.any(np.isinf(data)):
                return {"success": False, "error": "Infinite values"}

            model = ARIMA(data, order=order)
            fitted = model.fit()

            return {
                "model": fitted,
                "aic": round(float(fitted.aic), 2),
                "bic": round(float(fitted.bic), 2),
                "success": True,
                "order": order
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def auto_arima(self, series: list) -> dict:
        """Try multiple ARIMA orders, return best by AIC."""
        orders = [
            (1, 1, 1), (1, 1, 0), (0, 1, 1),
            (2, 1, 1), (1, 1, 2), (0, 1, 2),
        ]

        best_result = None
        best_aic = float("inf")

        for order in orders:
            result = self.fit_arima(series, order)
            if result.get("success"):
                aic = result["aic"]
                if aic < best_aic:
                    best_aic = aic
                    best_result = result

        if best_result:
            logger.info(
                f"Best ARIMA{best_result['order']} "
                f"| AIC={best_aic:.2f}"
            )
        return best_result or {"success": False}

    def forecast_arima(
        self, series: list, steps: int = 12
    ) -> dict:
        """ARIMA forecast with robust fallback."""
        result = self.auto_arima(series)

        if not result.get("success"):
            logger.warning("ARIMA failed → linear trend")
            return self._linear_trend_forecast(series, steps)

        try:
            fitted = result["model"]
            fc_obj = fitted.get_forecast(steps=steps)
            predicted = np.array(
                fc_obj.predicted_mean, dtype=float
            )
            conf = fc_obj.conf_int(alpha=0.05)

            predicted = np.clip(
                np.nan_to_num(predicted, nan=0.0), 0, None
            )
            lower = np.clip(
                np.nan_to_num(
                    np.array(conf.iloc[:, 0], dtype=float),
                    nan=0.0
                ), 0, None
            )
            upper = np.nan_to_num(
                np.array(conf.iloc[:, 1], dtype=float),
                nan=0.0
            )

            return {
                "method": "ARIMA",
                "order": str(result["order"]),
                "aic": float(result["aic"]),
                "forecast": [float(round(v)) for v in predicted],
                "lower_bound": [float(round(v)) for v in lower],
                "upper_bound": [float(round(v)) for v in upper],
                "steps": int(steps)
            }

        except Exception as e:
            logger.error(f"ARIMA forecast error: {e}")
            return self._linear_trend_forecast(series, steps)

    def _linear_trend_forecast(
        self, series: list, steps: int
    ) -> dict:
        """Linear trend fallback - always works."""
        try:
            data = np.array(series[-24:], dtype=float)
            mean_val = float(np.nanmean(data))
            data = np.nan_to_num(data, nan=mean_val)
            x = np.arange(len(data), dtype=float)

            coeffs = np.polyfit(x, data, 1)
            slope = float(coeffs[0])
            intercept = float(coeffs[1])

            forecast = []
            for i in range(steps):
                pred = slope * (len(data) + i) + intercept
                forecast.append(float(max(0.0, round(pred))))

            lower = [float(max(0.0, v * 0.85)) for v in forecast]
            upper = [float(v * 1.15) for v in forecast]

            logger.info(f"Linear trend | slope={slope:.2f}")
            return {
                "method": "Linear Trend",
                "forecast": forecast,
                "lower_bound": lower,
                "upper_bound": upper,
                "steps": int(steps),
                "slope": slope
            }

        except Exception as e:
            logger.error(f"Linear trend error: {e}")
            last_val = float(series[-1]) if series else 1500.0
            return {
                "method": "Constant",
                "forecast": [last_val] * steps,
                "lower_bound": [last_val * 0.85] * steps,
                "upper_bound": [last_val * 1.15] * steps,
                "steps": int(steps)
            }

    def exponential_smoothing(
        self, series: list, steps: int = 12
    ) -> dict:
        """Holt-Winters exponential smoothing."""
        try:
            from statsmodels.tsa.holtwinters import (
                ExponentialSmoothing
            )

            data = np.array(series, dtype=float)
            mean_val = float(np.nanmean(data))
            data = np.nan_to_num(data, nan=mean_val)

            use_seasonal = len(data) >= 24

            model = ExponentialSmoothing(
                data,
                trend="add",
                seasonal="add" if use_seasonal else None,
                seasonal_periods=12 if use_seasonal else None,
                initialization_method="estimated"
            )
            fitted = model.fit(optimized=True, use_brute=False)
            fc = np.array(fitted.forecast(steps), dtype=float)
            fc = np.clip(
                np.nan_to_num(fc, nan=data[-1]), 0, None
            )

            return {
                "method": "Holt-Winters Exponential Smoothing",
                "forecast": [float(round(v)) for v in fc],
                "steps": int(steps)
            }

        except Exception as e:
            logger.warning(f"Exp smoothing failed: {e}")
            return self._linear_trend_forecast(series, steps)

    def generate_future_dates(
        self, last_date, steps: int = 12
    ) -> list:
        """
        Generate future month date strings.

        Args:
            last_date: Can be string "2024-05-01", 
                      Timestamp, or date object
            steps: Number of future months

        Returns:
            List of "YYYY-MM" strings
        """
        try:
            # Handle all possible input types
            if isinstance(last_date, str):
                # Could be "2024-05" or "2024-05-01"
                if len(last_date) == 7:
                    last_date = last_date + "-01"
                last_ts = pd.Timestamp(last_date)
            elif isinstance(last_date, pd.Timestamp):
                last_ts = last_date
            else:
                # datetime.date or similar
                last_ts = pd.Timestamp(str(last_date))

            dates = []
            for i in range(1, int(steps) + 1):
                future = last_ts + pd.DateOffset(months=i)
                dates.append(future.strftime("%Y-%m"))

            return dates

        except Exception as e:
            logger.error(f"Date generation error: {e}")
            # Fallback: generate from current date
            now = pd.Timestamp.now()
            return [
                (now + pd.DateOffset(months=i)).strftime("%Y-%m")
                for i in range(1, int(steps) + 1)
            ]
