//
// Created by andrey on 05.10.23.
//
#include "../include/CryptographicLibrary/Cryptographer.h"
#include "Impl_Cryptographer.h"

namespace Lucifer {
    Cryptographer::Cryptographer(BaseTools::ByteArray key)
            : pImpl(std::make_unique<Impl_Cryptographer>(std::move(key))){}
    Cryptographer::~Cryptographer() = default;

    Cryptographer::Cryptographer(Cryptographer &&_rhs)noexcept = default;

    Cryptographer &Cryptographer::operator=(Cryptographer &&_rhs)noexcept= default;

    Cryptographer::Cryptographer(Cryptographer &_rhs)//глубокое копирование
            : pImpl(nullptr){
        if(_rhs.pImpl) pImpl = std::make_unique<Impl_Cryptographer>(*_rhs.pImpl);
    }

    Cryptographer &Cryptographer::operator=(const Cryptographer &_rhs){//глубокое копирование
        if(!_rhs.pImpl) pImpl.reset();
        else if(!pImpl) pImpl = std::make_unique<Impl_Cryptographer> (*_rhs.pImpl);
        else *pImpl = *_rhs.pImpl;
        return *this;
    }

    BaseTools::ByteArray Cryptographer::encrypt(const BaseTools::ByteArray &message) {
        return  pImpl->encrypt(message);
    }

    BaseTools::ByteArray Cryptographer::encrypt(const BaseTools::ByteArray &message, int threadCount) {
        return  pImpl->encrypt(message, threadCount);
    }

    BaseTools::ByteArray Cryptographer::decrypt(const BaseTools::ByteArray &message) {
        return  pImpl->decrypt(message);
    }


} // namespace Namespace