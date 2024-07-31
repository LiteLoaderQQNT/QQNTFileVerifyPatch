#pragma once
#include <Windows.h>
#include <cstdio>
#include <string>
#include <vector>

std::uint8_t* sig(const HMODULE module, const std::string& byte_array);