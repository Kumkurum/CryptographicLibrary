//
// Created by andrey on 05.10.23.
//

#ifndef CRYPTOGRAPHICLIBRARY_IMPL_CRYPTOGRAPHER_H
#define CRYPTOGRAPHICLIBRARY_IMPL_CRYPTOGRAPHER_H
#include <cstddef>
#include <BaseTools/ByteArray.h>
#include <string>
#include <vector>
#include <bitset>
#include <BaseTools/BitSet64.h>

namespace Lucifer {
    class Impl_Cryptographer {
    public:
        explicit Impl_Cryptographer(BaseTools::ByteArray  key);
        //interface
        BaseTools::ByteArray encrypt(const BaseTools::ByteArray& message);
        BaseTools::ByteArray encrypt(const BaseTools::ByteArray& message, int threadCount);

        BaseTools::ByteArray decrypt(const BaseTools::ByteArray& message);
        BaseTools::ByteArray decrypt(const BaseTools::ByteArray& message, int threadCount);
    private:
        void cryptBlocks(std::vector<BaseTools::BitSet64>& parts);
        void decryptBlocks(std::vector<BaseTools::BitSet64>& parts);
        void generateKeys();
        int getZeroChar(BaseTools::BitSet64 backBlock);

        BaseTools::BitSet64 _key;
        BaseTools::BitSet64 _keyRound[16];
    };
}
#endif //CRYPTOGRAPHICLIBRARY_IMPL_CRYPTOGRAPHER_H
