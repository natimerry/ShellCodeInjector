#pragma once
#ifndef MetaString_h
#define MetaString_h

#include "Inline.h"
#include "Indexes.h"
#include "MetaRandom.h"
#include "Log.h"

namespace andrivet {
    namespace ADVobfuscator {

        // Represents an obfuscated string, parametrized with an alrorithm number N, a list of indexes Indexes and a key Key

        template<int N, char Key, typename Indexes>
        struct MetaString;

        // Partial specialization with a list of indexes I, a key K and algorithm N = 0
        // Each character is encrypted (XOR) with the same key

        template<char K, int... I>
        struct MetaString<0, K, Indexes<I...>>
        {
            // Constructor. Evaluated at compile time.
            constexpr ALWAYS_INLINE MetaString(const char* str)
                : key_{ K }, buffer_{ encrypt(str[I], K)... } { }

            // Runtime decryption. Most of the time, inlined
            inline const char* decrypt()
            {
                for (size_t i = 0; i < sizeof...(I); ++i)
                    buffer_[i] = decrypt(buffer_[i]);
                buffer_[sizeof...(I)] = 0;
                LOG("--- Implementation #" << 0 << " with key 0x" << hex(key_));
                return const_cast<const char*>(buffer_);
            }

        private:
            // Encrypt / decrypt a character of the original string with the key
            constexpr char key() const { return key_; }
            constexpr char ALWAYS_INLINE encrypt(char c, int k) const { return c ^ k; }
            constexpr char decrypt(char c) const { return encrypt(c, key()); }

            volatile int key_; // key. "volatile" is important to avoid uncontrolled over-optimization by the compiler
            volatile char buffer_[sizeof...(I) + 1]; // Buffer to store the encrypted string + terminating null byte
        };

        // Partial specialization with a list of indexes I, a key K and algorithm N = 1
        // Each character is encrypted (XOR) with an incremented key.

        template<char K, int... I>
        struct MetaString<1, K, Indexes<I...>>
        {
            // Constructor. Evaluated at compile time.
            constexpr ALWAYS_INLINE MetaString(const char* str)
                : key_(K), buffer_{ encrypt(str[I], I)... } { }

            // Runtime decryption. Most of the time, inlined
            inline const char* decrypt()
            {
                for (size_t i = 0; i < sizeof...(I); ++i)
                    buffer_[i] = decrypt(buffer_[i], i);
                buffer_[sizeof...(I)] = 0;
                LOG("--- Implementation #" << 1 << " with key 0x" << hex(key_));
                return const_cast<const char*>(buffer_);
            }

        private:
            // Encrypt / decrypt a character of the original string with the key
            constexpr char key(size_t position) const { return static_cast<char>(key_ + position); }
            constexpr char ALWAYS_INLINE encrypt(char c, size_t position) const { return c ^ key(position); }
            constexpr char decrypt(char c, size_t position) const { return encrypt(c, position); }

            volatile int key_; // key. "volatile" is important to avoid uncontrolled over-optimization by the compiler
            volatile char buffer_[sizeof...(I) + 1]; // Buffer to store the encrypted string + terminating null byte
        };

        // Partial specialization with a list of indexes I, a key K and algorithm N = 2
        // Shift the value of each character and does not store the key. It is only used at compile-time.

        template<char K, int... I>
        struct MetaString<2, K, Indexes<I...>>
        {
            // Constructor. Evaluated at compile time. Key is *not* stored
            constexpr ALWAYS_INLINE MetaString(const char* str)
                : buffer_{ encrypt(str[I])..., 0 } { }

            // Runtime decryption. Most of the time, inlined
            inline const char* decrypt()
            {
                for (size_t i = 0; i < sizeof...(I); ++i)
                    buffer_[i] = decrypt(buffer_[i]);
                LOG("--- Implementation #" << 2 << " with key 0x" << hex(K));
                return const_cast<const char*>(buffer_);
            }

        private:
            // Encrypt / decrypt a character of the original string with the key
            // Be sure that the encryption key is never 0.
            constexpr char key(char key) const { return 1 + (key % 13); }
            constexpr char ALWAYS_INLINE encrypt(char c) const { return c + key(K); }
            constexpr char decrypt(char c) const { return c - key(K); }

            // Buffer to store the encrypted string + terminating null byte. Key is not stored
            volatile char buffer_[sizeof...(I) + 1];
        };

        // Helper to generate a key
        template<int N>
        struct MetaRandomChar
        {
            // Use 0x7F as maximum value since most of the time, char is signed (we have however 1 bit less of randomness)
            static const char value = static_cast<char>(1 + MetaRandom<N, 0x7F - 1>::value);
        };


    }
}

// Prefix notation
#define DEF_OBFUSCATED(str) andrivet::ADVobfuscator::MetaString<andrivet::ADVobfuscator::MetaRandom<__COUNTER__, 3>::value, andrivet::ADVobfuscator::MetaRandomChar<__COUNTER__>::value, andrivet::ADVobfuscator::Make_Indexes<sizeof(str) - 1>::type>(str)

#define OBFUSCATED(str) (DEF_OBFUSCATED(str).decrypt())

#endif