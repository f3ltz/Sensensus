#include <Arduino.h>

// The extern "C" prevents C++ name mangling so the TFLite core can find this exact function name
extern "C" void DebugLog(const char* s) {
    // Route TFLM internal logs to the standard Arduino Serial monitor
    Serial.print(s);
}