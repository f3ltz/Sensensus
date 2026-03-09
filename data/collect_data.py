import serial
import time
import csv
import sys
import threading

# --- Configuration for Data Collection ---
PORT = '/dev/ttyACM0'
BAUD_RATE = 115200
DUMMY_VALUE = "SYNC"

# ==========================================
# HACKATHON CONFIGURATION
CURRENT_LABEL = "3"  # e.g., "Drop", "Flipped_X", "Flipped_Y"
CSV_FILENAME = "label_3"
# ==========================================

# --- Global Recording State ---
is_recording = False
samples_collected_this_session = 0
total_samples = 0

def toggle_recording():
    """Runs in a background thread, waiting for the Enter key."""
    global is_recording, samples_collected_this_session
    while True:
        try:
            input()  # Blocks until the user presses Enter
            is_recording = not is_recording
            
            if is_recording:
                samples_collected_this_session = 0
                print("\n" + "="*40)
                print(f" 🔴 RECORDING STARTED FOR: '{CURRENT_LABEL}'")
                print("="*40 + "\n")
            else:
                print("\n" + "="*40)
                print(f" ⏸️ RECORDING PAUSED. Saved {samples_collected_this_session} samples.")
                print(f" Total samples collected so far: {total_samples}")
                print(" Press [ENTER] to record the next batch...")
                print("="*40 + "\n")
        except EOFError:
            break

# --- Setup Serial Connection ---
try:
    ser = serial.Serial(PORT, BAUD_RATE, timeout=0.1)
    ser.flushInput()
    print(f"Connected to {PORT} successfully.")
except serial.SerialException as e:
    print(f"Error opening {PORT}: {e}")
    sys.exit(1)

# Start the keyboard listener thread
thread = threading.Thread(target=toggle_recording, daemon=True)
thread.start()

text_buffer = ""
state = "WAIT_SYNC"
temp_qr = temp_qi = temp_qj = temp_qk = 0.0
temp_ax = temp_ay = 0.0

print(f"Current Label: '{CURRENT_LABEL}'")
print(f"Saving to: {CSV_FILENAME}")
print("\n>>> PRESS [ENTER] TO START/STOP RECORDING <<<")
print("Press [Ctrl+C] to quit the program completely.\n")

# --- Open CSV and Start Logging ---
with open(CSV_FILENAME, mode='a', newline='') as csv_file:
    writer = csv.writer(csv_file)
    
    if csv_file.tell() == 0:
        writer.writerow([
            "Timestamp", "LinAccX", "LinAccY", "LinAccZ", 
            "QuatI", "QuatJ", "QuatK", "QuatReal", "Label"
        ])

    try:
        while True:
            if ser.in_waiting > 0:
                try:
                    raw_data = ser.read(ser.in_waiting).decode('utf-8')
                    text_buffer += raw_data
                except UnicodeDecodeError:
                    pass 
                    
                if ',' in text_buffer:
                    tokens = text_buffer.split(',')
                    text_buffer = tokens.pop() 
                    
                    for token in tokens:
                        token = token.strip()
                        if not token: continue
                        
                        if state == "WAIT_SYNC":
                            if token == DUMMY_VALUE: state = "READ_QR"
                        elif state == "READ_QR":
                            try: temp_qr = float(token); state = "READ_QI"
                            except ValueError: state = "WAIT_SYNC"
                        elif state == "READ_QI":
                            try: temp_qi = float(token); state = "READ_QJ"
                            except ValueError: state = "WAIT_SYNC"
                        elif state == "READ_QJ":
                            try: temp_qj = float(token); state = "READ_QK"
                            except ValueError: state = "WAIT_SYNC"
                        elif state == "READ_QK":
                            try: temp_qk = float(token); state = "READ_AX"
                            except ValueError: state = "WAIT_SYNC"
                        elif state == "READ_AX":
                            try: temp_ax = float(token); state = "READ_AY"
                            except ValueError: state = "WAIT_SYNC"
                        elif state == "READ_AY":
                            try: temp_ay = float(token); state = "READ_AZ"
                            except ValueError: state = "WAIT_SYNC"
                        elif state == "READ_AZ":
                            try:
                                temp_az = float(token)
                                
                                # ONLY WRITE TO CSV IF WE ARE RECORDING
                                if is_recording:
                                    timestamp = int(time.time() * 1000)
                                    writer.writerow([
                                        timestamp, 
                                        temp_ax, temp_ay, temp_az, 
                                        temp_qi, temp_qj, temp_qk, temp_qr, 
                                        CURRENT_LABEL
                                    ])
                                    samples_collected_this_session += 1
                                    total_samples += 1
                                    
                                state = "WAIT_SYNC" 
                            except ValueError:
                                state = "WAIT_SYNC"

    except KeyboardInterrupt:
        print("\n\nProgram terminated by user.")
        print(f"Successfully saved a total of {total_samples} new samples to {CSV_FILENAME}.")
        ser.close()
        sys.exit(0)