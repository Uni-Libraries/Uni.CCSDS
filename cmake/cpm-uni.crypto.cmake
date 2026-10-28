# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2022-2025 Uni-Libraries contributors

if(NOT TARGET uni_crypto)
    CPMAddPackage(
            NAME uni.crypto
            GITHUB_REPOSITORY Uni-Libraries/Uni.Crypto
            GIT_TAG 3d75cfb8cfa40e6854ec2d6b92fea2edbd43dc1b
    )
endif()
