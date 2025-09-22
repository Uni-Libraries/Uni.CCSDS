# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2022-2025 Uni-Libraries contributors

if(NOT TARGET uni.crypto)
    CPMAddPackage(
            NAME uni.crypto
            GITHUB_REPOSITORY Uni-Libraries/Uni.Crypto
            GIT_TAG 54da67ca0a1a73f8d51c99d6e98ad95c77436cbe
    )
endif()
