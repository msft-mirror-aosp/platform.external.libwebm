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

#pragma once

#include <stdint.h>
#include <vector>

#include "mkvmuxer/mkvmuxer.h"
#include "fuzzer/FuzzedDataProvider.h"

class DiscardingMkvWriter : public mkvmuxer::IMkvWriter {
public:
  DiscardingMkvWriter();

  mkvmuxer::int32 Write(const void* buf, mkvmuxer::uint32 len) override;
  mkvmuxer::int64 Position() const override;
  mkvmuxer::int32 Position(mkvmuxer::int64 position) override;
  bool Seekable() const override;
  void ElementStartNotify(mkvmuxer::uint64, mkvmuxer::int64) override;

private:
  mkvmuxer::int64 position_;
  mkvmuxer::int64 checksum_;
};

std::vector<uint8_t> FuzzerRandomLengthBytes(FuzzedDataProvider&);
