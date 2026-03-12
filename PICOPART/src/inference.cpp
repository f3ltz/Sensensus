#include "inference.h"
#include "config.h"
#include <Arduino.h>
#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"
#include "tensorflow/lite/schema/schema_generated.h"

float g_lastConfidence = 0.0f;

static uint8_t                           _tensor_arena[TENSOR_ARENA_SIZE];
static tflite::MicroInterpreter         *_interpreter = nullptr;
static TfLiteTensor                     *_input       = nullptr;
static TfLiteTensor                     *_output      = nullptr;
static tflite::MicroMutableOpResolver<16> _resolver;

bool infer_init(const unsigned char *model_data, size_t /*model_len*/) {
    const tflite::Model *model = tflite::GetModel(model_data);
    if (model->version() != TFLITE_SCHEMA_VERSION) {
        Serial.println("[Infer] Schema version mismatch");
        return false;
    }

    _resolver.AddConv2D();
    _resolver.AddFullyConnected();
    _resolver.AddRelu();
    _resolver.AddReshape();
    _resolver.AddSoftmax();
    _resolver.AddMaxPool2D();
    _resolver.AddExpandDims();
    _resolver.AddMul();
    _resolver.AddAdd(); 
    _resolver.AddLogistic();
    _resolver.AddMean();
    _resolver.AddRsqrt();

    static tflite::MicroInterpreter interp(
        model, _resolver, _tensor_arena, TENSOR_ARENA_SIZE);
    _interpreter = &interp;

    if (_interpreter->AllocateTensors() != kTfLiteOk) {
        _interpreter = nullptr;
        Serial.println("[Infer] AllocateTensors() failed — increase TENSOR_ARENA_SIZE");
        return false;
    }

    _input  = _interpreter->input(0);
    _output = _interpreter->output(0);

    if (_input->dims->size != 3 ||
        _input->dims->data[1] != 50 ||
        _input->dims->data[2] != 7 ||
        _input->type != kTfLiteInt8) {
        Serial.printf("[Infer] Bad input tensor: dims=%d shape=[%d,%d,%d] type=%d\n",
            _input->dims->size,
            _input->dims->data[0],
            _input->dims->data[1],
            _input->dims->data[2],
            _input->type);
        _interpreter = nullptr;
        return false;
    }

    if (_output->dims->data[1] != 1 || _output->type != kTfLiteInt8) {
        Serial.printf("[Infer] Bad output tensor: shape=[%d,%d] type=%d\n",
            _output->dims->data[0],
            _output->dims->data[1],
            _output->type);
        _interpreter = nullptr;
        return false;
    }

    Serial.printf("[Infer] Model loaded OK. input scale=%.6f zp=%d\n",
        _input->params.scale, _input->params.zero_point);
    return true;
}

float infer_run(const float *window_flat) {
    if (!_interpreter) return -1.0f;

    // Quantize float32 input → int8
    float scale      = _input->params.scale;
    int   zero_point = _input->params.zero_point;

    if (scale == 0.0f) {
        Serial.println("[Infer] Input scale is 0 — model quantization params missing");
        return -1.0f;
    }

    for (int i = 0; i < INPUT_TENSOR_SIZE; i++) {
        int q = (int)(window_flat[i] / scale) + zero_point;
        if (q < -128) q = -128;
        if (q >  127) q =  127;
        _input->data.int8[i] = (int8_t)q;
    }

    if (_interpreter->Invoke() != kTfLiteOk) {
        Serial.println("[Infer] Invoke() failed");
        return -1.0f;
    }

    float out_scale      = _output->params.scale;
    int   out_zero_point = _output->params.zero_point;
    float p_drop = (_output->data.int8[0] - out_zero_point) * out_scale;
    g_lastConfidence = p_drop;
    Serial.printf("[Infer] p_drop=%.4f\n", p_drop);
    return p_drop;
}