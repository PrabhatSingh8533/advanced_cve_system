"""
CVE Time Series Synthetic Data Generator.
Dynamically uses current date - always up to date.
"""

import random
import numpy as np
import pandas as pd
from datetime import datetime, date, timedelta
from loguru import logger


class CVETimeSeriesGenerator:
    """
    Generates realistic CVE time series data.
    Always generates up to CURRENT month dynamically.
    """

    # Real approximate CVE counts per year (from NVD)
    YEARLY_TOTALS = {
        2015: 6487,
        2016: 6447,
        2017: 14714,
        2018: 16555,
        2019: 17305,
        2020: 18325,
        2021: 20155,
        2022: 25096,
        2023: 29065,
        2024: 40000,
        2025: 45000,  # Projected based on trend
        2026: 48000,  # Projected
    }

    EXPLOIT_DISTRIBUTION = {
        "exploit_remote_code_execution": 0.18,
        "exploit_sql_injection": 0.08,
        "exploit_cross_site_scripting": 0.14,
        "exploit_buffer_overflow": 0.12,
        "exploit_denial_of_service": 0.15,
        "exploit_privilege_escalation": 0.10,
        "exploit_path_traversal": 0.06,
        "exploit_authentication_bypass": 0.09,
        "exploit_information_disclosure": 0.08,
    }

    SEVERITY_DISTRIBUTION = {
        "sev_critical": 0.08,
        "sev_high": 0.32,
        "sev_medium": 0.42,
        "sev_low": 0.18,
    }

    OS_DISTRIBUTION = {
        "Windows": 0.28,
        "Linux": 0.25,
        "Android": 0.12,
        "iOS": 0.06,
        "macOS": 0.05,
        "Web Application": 0.14,
        "Network Device": 0.06,
        "Other": 0.04,
    }

    MONTHLY_WEIGHTS = {
        1: 0.85, 2: 0.90, 3: 0.95,
        4: 1.00, 5: 1.05, 6: 1.10,
        7: 0.90, 8: 0.95, 9: 1.05,
        10: 1.10, 11: 1.05, 12: 0.80,
    }

    def __init__(self):
        random.seed(42)
        np.random.seed(42)
        # Always use current date dynamically
        self.today = datetime.now()
        self.current_year = self.today.year
        self.current_month = self.today.month
        logger.info(
            f"CVETimeSeriesGenerator initialized | "
            f"Current date: {self.today.strftime('%Y-%m-%d')}"
        )

    def _get_yearly_total(self, year: int) -> int:
        """
        Get yearly total - uses real data if available,
        projects for future years.
        """
        if year in self.YEARLY_TOTALS:
            return self.YEARLY_TOTALS[year]

        # Project using exponential growth trend
        # CVEs growing ~15% per year on average
        base_year = 2023
        base_count = self.YEARLY_TOTALS[base_year]
        years_ahead = year - base_year
        projected = int(base_count * (1.15 ** years_ahead))
        logger.info(f"Projected {year} CVEs: {projected}")
        return projected

    def generate_monthly_counts(
        self,
        start_year: int = 2015,
        end_year: int = None  # None = current year
    ) -> pd.DataFrame:
        """
        Generate monthly CVE counts up to current month.

        Args:
            start_year: Start year for data
            end_year: End year (default: current year)
        """
        # Always extend to current year/month
        if end_year is None:
            end_year = self.current_year

        records = []

        for year in range(start_year, end_year + 1):
            yearly_total = self._get_yearly_total(year)

            monthly_weights = [
                self.MONTHLY_WEIGHTS[m] for m in range(1, 13)
            ]
            total_weight = sum(monthly_weights)

            # Determine how many months to include
            if year == end_year:
                max_month = self.current_month  # Only up to now
            else:
                max_month = 12

            for month in range(1, max_month + 1):
                weight = self.MONTHLY_WEIGHTS[month]
                base = int(yearly_total * weight / total_weight)
                noise = int(np.random.normal(0, base * 0.08))
                count = max(100, base + noise)

                # Scale down partial year (current year may not be complete)
                if year == self.current_year:
                    # Only count what's been published so far
                    days_in_month = 30
                    days_passed = min(
                        days_in_month,
                        (self.today - datetime(year, month, 1)).days
                        if month == self.current_month
                        else days_in_month
                    )
                    count = int(count * (days_passed / days_in_month))
                    count = max(10, count)

                sev = {
                    k: int(count * v)
                    for k, v in self.SEVERITY_DISTRIBUTION.items()
                }
                exploit = {
                    k: int(count * v)
                    for k, v in self.EXPLOIT_DISTRIBUTION.items()
                }

                records.append({
                    "date": pd.Timestamp(date(year, month, 1)),
                    "year": year,
                    "month": month,
                    "total_cves": count,
                    **sev,
                    **exploit,
                })

        df = pd.DataFrame(records)
        df = df.sort_values("date").reset_index(drop=True)

        logger.info(
            f"Generated {len(df)} monthly records "
            f"({start_year} to {end_year}, "
            f"through {self.current_year}-{self.current_month:02d})"
        )
        return df

    def generate_rce_trend(
        self,
        start_year: int = 2015,
        end_year: int = None
    ) -> pd.DataFrame:
        """Generate RCE trend data up to current date."""
        if end_year is None:
            end_year = self.current_year

        monthly_df = self.generate_monthly_counts(
            start_year, end_year
        )

        # RCE growing as % of total each year
        rce_growth = {
            2015: 0.15, 2016: 0.16, 2017: 0.17,
            2018: 0.18, 2019: 0.20, 2020: 0.22,
            2021: 0.23, 2022: 0.24, 2023: 0.25,
            2024: 0.27, 2025: 0.28, 2026: 0.29,
        }

        records = []
        for _, row in monthly_df.iterrows():
            yr = row["year"]
            pct = rce_growth.get(yr, 0.20)
            noise = np.random.normal(1.0, 0.10)
            rce = max(1, int(row["total_cves"] * pct * noise))
            records.append({
                "date": row["date"],
                "year": yr,
                "month": row["month"],
                "total_cves": row["total_cves"],
                "rce_count": rce,
                "rce_percentage": round(
                    rce / row["total_cves"] * 100, 2
                )
            })

        return pd.DataFrame(records)

    def generate_os_trend(
        self,
        start_year: int = 2018,
        end_year: int = None
    ) -> pd.DataFrame:
        """Generate OS distribution up to current year."""
        if end_year is None:
            end_year = self.current_year

        os_growth = {
            "Windows": 1.05,
            "Linux": 1.18,       # Faster growth (cloud)
            "Android": 1.20,     # Mobile growth
            "iOS": 1.10,
            "macOS": 1.12,
            "Web Application": 1.28,  # Fastest (web era)
            "Network Device": 1.10,
            "Other": 1.05,
        }

        records = []
        for year in range(start_year, end_year + 1):
            yearly = self._get_yearly_total(year)

            # Partial year adjustment
            if year == self.current_year:
                yearly = int(
                    yearly * self.current_month / 12
                )

            for os_name, base_pct in self.OS_DISTRIBUTION.items():
                years_from = year - start_year
                growth = os_growth.get(os_name, 1.05)
                adj_pct = base_pct * (growth ** years_from)
                count = int(yearly * adj_pct)
                noise = int(np.random.normal(0, count * 0.1))
                records.append({
                    "year": year,
                    "os": os_name,
                    "count": max(10, count + noise),
                    "percentage": round(adj_pct * 100, 2)
                })

        return pd.DataFrame(records)

    def get_current_period_label(self) -> str:
        """Get human-readable current period."""
        return self.today.strftime("%B %Y")
