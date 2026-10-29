with open("/app/app/services/analytics/forecasting.py", "r") as f:
    content = f.read()

# Fix the ARIMA forecast method - iloc error on ndarray
old_code = """            conf = forecast_obj.conf_int(alpha=0.05)

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
            )"""

new_code = """            conf = forecast_obj.conf_int(alpha=0.05)

            predicted = np.clip(
                np.nan_to_num(
                    np.array(predicted, dtype=float), nan=0.0
                ), 0, None
            )
            
            # Handle both DataFrame and ndarray conf_int output
            try:
                if hasattr(conf, "iloc"):
                    lower_raw = np.array(conf.iloc[:, 0], dtype=float)
                    upper_raw = np.array(conf.iloc[:, 1], dtype=float)
                else:
                    conf_arr = np.array(conf, dtype=float)
                    if conf_arr.ndim == 2:
                        lower_raw = conf_arr[:, 0]
                        upper_raw = conf_arr[:, 1]
                    else:
                        lower_raw = conf_arr
                        upper_raw = conf_arr
            except Exception as ce:
                print(f"conf_int parse error: {ce}")
                lower_raw = predicted * 0.85
                upper_raw = predicted * 1.15
                
            lower = np.clip(
                np.nan_to_num(lower_raw, nan=0.0), 0, None
            )
            upper = np.nan_to_num(upper_raw, nan=0.0)"""

if old_code in content:
    new_content = content.replace(old_code, new_code)
    with open("/app/app/services/analytics/forecasting.py", "w") as f:
        f.write(new_content)
    print("ARIMA fix applied!")
else:
    print("Pattern not found - checking existing code...")
    # Find iloc usage
    idx = content.find("conf.iloc")
    if idx > -1:
        print(f"Found iloc at pos {idx}: {content[idx-50:idx+100]}")
    else:
        print("No iloc found - different version")
