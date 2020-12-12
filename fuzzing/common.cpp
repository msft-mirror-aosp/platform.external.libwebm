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

#include "fuzzing/common.h"

using mkvmuxer::int32;
using mkvmuxer::int64;
using mkvmuxer::uint32;
using mkvmuxer::uint64;

DiscardingMkvWriter::DiscardingMkvWriter() : position_(0), checksum_(0) {}

int32 DiscardingMkvWriter::Write(const void* buf, uint32 len) {
  auto data = static_cast<const uint8_t*>(buf);
  for (uint32 i = 0; i < len; i++) {
    // Force reads on all data in buf so ASAN can validate it
    checksum_ += data[i];
  }
  position_ += len;
  return 0;
}

int64 DiscardingMkvWriter::Position() const {
  return position_;
}

int32 DiscardingMkvWriter::Position(int64 position) {
  position_ = position;
  return 0;
}

bool DiscardingMkvWriter::Seekable() const {
  return true;
}

void DiscardingMkvWriter::ElementStartNotify(uint64, int64) {
}

std::vector<uint8_t> FuzzerRandomLengthBytes(FuzzedDataProvider& fdp) {
  // https://github.com/google/fuzzing/blob/master/docs/split-inputs.md#main-concepts
  // ConsumeRandomLengthString is a good source of data, but we have to remove
  // the null terminator to not hide off-by-one access errors.
  std::string str = fdp.ConsumeRandomLengthString();
  std::vector<uint8_t> data(str.begin(), str.end());
  return data;
}
