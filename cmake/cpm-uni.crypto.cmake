# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2022-2025 Uni-Libraries contributors

if(NOT TARGET uni_crypto)
    CPMAddPackage(
            NAME uni.crypto
            GITHUB_REPOSITORY Uni-Libraries/Uni.Crypto
            GIT_TAG 4c58ff9fd8184f735aaadfdd15c7e5023130267e
    )
endif()
