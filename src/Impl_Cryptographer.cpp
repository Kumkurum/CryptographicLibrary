//
// Created by andrey on 05.10.23.
//

#include "Impl_Cryptographer.h"
#include <memory>
#include <vector>
#include <thread>
#include <BaseTools/Debug.h>
namespace Lucifer {
    using namespace BaseTools;

    Impl_Cryptographer::Impl_Cryptographer(BaseTools::ByteArray  key): _key{key.data(), static_cast<int>(key.size())}{
        generateKeys();

    }

    constexpr int  tableKeyChange[56]{
            56,48,40,32,24,16,8,0,57,49,41,33,25,17,
            9,1,58,50,42,34,26,18,10,2,59,51,43,35,
            62,54,46,38,30,22,14,6,61,53,45,37,29,21,
            13,5,60,52,44,36,28,20,12,4,27,19,11,3
    };

    void swapKey(BaseTools::BitSet64& key){
        uint64_t tmp{0};
        for(auto i{0}; i< 56; ++i)
            tmp |= (((key._bits>>(63-tableKeyChange[i]))&1)<<(55-i));
        key._bits = tmp;
    }

    constexpr uint64_t maskBit{~((uint64_t {1}<<28) | 1)};
    void rotate(BaseTools::BitSet64& key){//64 - 0
        auto bits55 = uint64_t(key[55]) << 28;
        auto bits27 = uint64_t(key[27]);

        key._bits<<=1;
        key._bits&= maskBit;

        key._bits|= bits55;
        key._bits |= bits27;
    }

    constexpr int  tableKeyChange2[48]{
            13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,
            25,7,15,6,26,19,12,1,40,51,30,36,46,54,29,39,
            50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31
    };
    BaseTools::BitSet64 getKeyRound(BaseTools::BitSet64& key){
        BitSet64 tmp;
        for(auto i{0}; i< 48; ++i)
            tmp._bits |= uint64_t(key[55 - tableKeyChange2[i]])<<(47 - i);
        return tmp;
    }

    constexpr int tableShiftKey[16]{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
    void Impl_Cryptographer::generateKeys() {
        swapKey(_key);
        for(auto i{0}; i< 16; ++i){
            for(auto j{0}; j<tableShiftKey[i]; ++j)
                rotate(_key);
            _keyRound[i] = getKeyRound(_key);
        }
    }
    std::vector<BitSet64> getParts(const std::byte* data, std::size_t size){
        auto wholePart{size/8};
        auto fractionalPart{size%8};
        std::vector<BitSet64> parts;
        parts.reserve(wholePart + bool(fractionalPart) );
        auto ptrPart = data;
        for(auto i{0} ; i < wholePart; ++i){
            parts.emplace_back(ptrPart, 8);
            ptrPart+=8;
        }
        if(fractionalPart)
            parts.emplace_back(ptrPart, fractionalPart);
        return parts;
    }
    constexpr int  tableChangeMsg[64]{
            57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7,
            56,48,40,32,24,16,8,0,58,50,42,34,26,18,10,2,
            60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6
    };
    void swapMsg(BitSet64& msg){
        uint64_t tmp{0};
        for(auto i{0}; i< 64; ++i)
            tmp |= (((msg._bits>>(63-tableChangeMsg[i]))&1)<<(63-i));
        msg._bits = tmp;
    }

    constexpr int  tableExpansion[48]{
            31,0,1,2,3,4,
            3,4,5,6,7,8,
            7,8,9,10,11,12,
            11,12,13,14,15,16,
            15,16,17,18,19,20,
            19,20,21,22,23,24,
            23,24,25,26,27,28,
            27,28,29,30,31,0
    };
    void expandPart(BitSet64& part){
        uint64_t tmp{0};
        for(auto i{0}; i< 48; ++i)
            tmp |= (((part._bits>>(31-tableExpansion[i]))&1)<<(47 -i));
        part._bits = tmp;
    }
    constexpr int sBlocks[8][4][16] = {
            {
                    { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
                    { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                    { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                    { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
            },
            {
                    { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                    { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                    { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                    { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
            },
            {
                    { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                    { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                    { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                    { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
            },
            {
                    { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                    { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                    { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                    { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
            },
            {
                    { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                    { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                    { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                    { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
            },
            {
                    { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                    { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                    { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                    { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
            },
            {
                    { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
                    { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
                    { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
                    { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
            },
            {
                    { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                    { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                    { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                    { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
            }
    };
    constexpr uint64_t columnMask(uint64_t{1}<<46 | uint64_t{1}<<45 | uint64_t{1}<<44 | uint64_t{1}<<43);
    constexpr int tableAfterSBlock[32]{
            15,6,19,20,28,11,27,16,
            0,14,22,25,4,17,30,9,
            1,7,23,13,31,26,2,8,
            18,12,29,5,21,10,3,24
    };
    void swapAfterBlock(BitSet64& part){
        uint64_t tmp{0};
        for(auto i{0}; i< 32; ++i)
            tmp |= (((part._bits>>(31-tableAfterSBlock[i]))&1)<<(31-i));
        part._bits = tmp;
    }

    BitSet64 sBlock(BitSet64& bits){
        int start{47};
        uint64_t tmpMask{columnMask};
        BitSet64 afterSBlocks;
        for(auto i{0}; i<8; ++i){
            int row( bits[start]);
            row<<=1;
            row |= bits[start-5];

            int column( (bits._bits & tmpMask)>>(start-4));
            tmpMask>>=6;
            start-=6;
            afterSBlocks._bits |=uint64_t(sBlocks[i][row][column])<<4*(7 - i);
        }
        swapAfterBlock(afterSBlocks);
        return afterSBlocks;
    }

    constexpr int finishTable[64]{
            39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,
            37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,
            35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,
            33,1,41,9,49,17,57,25,32,0,40,8,48,16,56,24
    };

    void finishSwap(BitSet64& msg){
        uint64_t tmp{0};
        for(auto i{0}; i< 64; ++i)
            tmp |= (((msg._bits>>(63-finishTable[i]))&1)<<(63-i));
        msg._bits = tmp;
    }

    void Impl_Cryptographer::cryptBlocks(std::vector<BitSet64>& parts){
        for(auto & part : parts) {
            swapMsg(part);
            BitSet64 l0{part._bits >> 32};
            BitSet64 r0{(part._bits << 32) >> 32};
            for (auto i{0}; i < 16; ++i) {
                uint64_t tmpR0{r0._bits};
                expandPart(r0);
                BitSet64 round(r0._bits ^ _keyRound[i]._bits);
                r0._bits = sBlock(round)._bits ^ l0._bits;
                l0._bits = tmpR0;
            }
            BitSet64 cryptPart{r0._bits << 32 | l0._bits};
            finishSwap(cryptPart);
            part = cryptPart;
        }
    }

    void Impl_Cryptographer::decryptBlocks(std::vector<BitSet64>& parts){
        for(auto & part : parts) {
            swapMsg(part);
            BitSet64 l0{part._bits >> 32};
            BitSet64 r0{(part._bits << 32) >> 32};
            for (auto i{15}; i >= 0; --i) {
                uint64_t tmpR0{r0._bits};
                expandPart(r0);
                BitSet64 round(r0._bits ^ _keyRound[i]._bits);
                r0._bits = sBlock(round)._bits ^ l0._bits;
                l0._bits = tmpR0;
            }
            BitSet64 cryptPart{r0._bits << 32 | l0._bits};
            finishSwap(cryptPart);
            part = cryptPart;
        }
    }

    void  lastBlockToChar(BitSet64 bitSet64, char* ptr) {
        for(int i{0}; i < 8; ++i){
            unsigned char symbol(bitSet64._bits>>56);
            bitSet64._bits<<=8;
            if(symbol == 0)
                return;
            ptr[i] = static_cast<char>(symbol);
        }
    }

    BaseTools::ByteArray Impl_Cryptographer::decrypt(const BaseTools::ByteArray &message) {
        auto parts = getParts(message.data(), message.size());
        decryptBlocks(parts);
        int zeroChar{0};
        BitSet64 backBlock{parts.back()._bits};
        for(auto i {7}; i >=0; --i){
            if(backBlock._bits>>(56) != 0)
                break;
            ++zeroChar;
            backBlock._bits<<=8;
        }
        BaseTools::ByteArray cryptByteArray{' ',parts.size() * 8 - zeroChar};
        char* ptr = reinterpret_cast<char*>(cryptByteArray.data());
        for(auto i{0}; i < parts.size()-1; ++i){
            parts[i].toChar(ptr);
            ptr+=8;
        }
        lastBlockToChar(backBlock, ptr);
        return cryptByteArray;
    }

    BaseTools::ByteArray Impl_Cryptographer::encrypt(const ByteArray &message) {
        auto parts = getParts(message.data(), message.size());
        cryptBlocks(parts);
        BaseTools::ByteArray cryptByteArray{' ',parts.size() * 8};
        char* ptr = reinterpret_cast<char*>(cryptByteArray.data());
        for(auto i{0}; i < parts.size(); ++i){
            parts[i].toChar(ptr);
            ptr+=8;
        }
        return cryptByteArray;
    }

    BaseTools::ByteArray Impl_Cryptographer::encrypt(const ByteArray &message, int threadCount) {
        std::unique_ptr<std::thread> threadPool[threadCount];
        if(threadCount > 1){
            auto sizePartMsg{ message.size() / 8 / threadCount};
            auto threadEncrypt = [this](std::byte *data, size_t size){
                auto parts = getParts(data, size);
                cryptBlocks(parts);
                BaseTools::ByteArray cryptByteArray{' ',parts.size() * 8};
                char* ptr = reinterpret_cast<char*>(cryptByteArray.data());
                for(auto i{0}; i < parts.size(); ++i){
                    parts[i].toChar(ptr);
                    ptr+=8;
                }
                return cryptByteArray;
            };
            for(auto i{0}; i < threadCount; ++i)
                threadPool[i] = std::make_unique<std::thread>(threadEncrypt,message.data(), message.size());
            for(auto i{0}; i < threadCount; ++i)
                threadPool[i]->join();
        }
    }
}