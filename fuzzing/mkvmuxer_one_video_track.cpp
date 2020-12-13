//
// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stddef.h>
#include <stdint.h>

#include <sstream>

#include "fuzzer/FuzzedDataProvider.h"
#include "mkvmuxer/mkvmuxer.h"
#include "fuzzing/common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  mkvmuxer::Segment segment;
  DiscardingMkvWriter writer;
  segment.Init(&writer);

  int width = fdp.ConsumeIntegral<int>();
  int height = fdp.ConsumeIntegral<int>();

  uint64_t video_track_number = segment.AddVideoTrack(width, height, 0);

  if (video_track_number == 0) {
    return 0;
  }

  while (fdp.remaining_bytes() > 0) {
    auto frame = FuzzerRandomLengthBytes(fdp);
    segment.AddFrame(
        frame.data(),
        frame.size(),
        video_track_number,
        fdp.ConsumeIntegral<uint64_t>(),
        fdp.ConsumeBool());
  }

  segment.Finalize();

  return 0;
}
