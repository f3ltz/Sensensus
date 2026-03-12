#include "tensorflow/lite/micro/micro_time.h"
#include <Arduino.h>

namespace tflite {

uint32_t ticks_per_second() {
    return 1000000; 
}

uint32_t GetCurrentTimeTicks() {
    // Return the standard Arduino micros() as an unsigned 32-bit int
    return static_cast<uint32_t>(micros());
}

} // namespace tflite