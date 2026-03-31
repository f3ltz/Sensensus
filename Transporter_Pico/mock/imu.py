import time

import numpy as np

from mock.constants import CSV_BUFFER_SAMPLES


def _generate_drop_csv(n_rows: int = CSV_BUFFER_SAMPLES) -> str:
    rows = []
    t    = int(time.time() * 1000) - n_rows * 20

    for i in range(n_rows):
        phase = i / n_rows
        if phase < 0.5:
            ax, ay, az = np.random.normal(0, 0.05, 3)
        elif phase < 0.75:
            ax, ay, az = np.random.normal(0, 0.01, 3)
        else:
            ax = np.random.normal(0,    2.0)
            ay = np.random.normal(0,    2.0)
            az = np.random.normal(-9.8, 3.0)

        qw = 1.0 + np.random.normal(0, 0.005)
        qx, qy, qz = np.random.normal(0, 0.005, 3)
        rows.append(f"{t},{ax:.6f},{ay:.6f},{az:.6f},{qw:.6f},{qx:.6f},{qy:.6f},{qz:.6f}")
        t += 20

    return "timestamp_ms,ax,ay,az,qw,qx,qy,qz\n" + "\n".join(rows)