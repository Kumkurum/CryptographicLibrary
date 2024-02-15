//
// Created by andrey on 05.10.23.
//

#ifndef CRYPTOGRAPHICLIBRARY_CRYPTOGRAPHER_H
#define CRYPTOGRAPHICLIBRARY_CRYPTOGRAPHER_H
#include <memory>
#include <BaseTools/ByteArray.h>

namespace Lucifer {
    class Impl_Cryptographer;
    /**
     * Класс для реализации алгоритма шифрования DESS
     */
    class Cryptographer {
    public:
        /**
         * @param key Ключ шифрования, используются первые 8 символов
         */
        explicit Cryptographer(BaseTools::ByteArray key);

        ~Cryptographer();
        Cryptographer(Cryptographer& _rhs);
        Cryptographer& operator=(const Cryptographer& _rhs);
        Cryptographer(Cryptographer&& _rhs) noexcept ;
        Cryptographer& operator=(Cryptographer&& _rhs)noexcept;

        /**
         * Функция для зашифровки сообщения
         * @param message - сообщение, которое требуется зашифровать
         * @return зашифрованное сообщение
         */
        BaseTools::ByteArray encrypt(const BaseTools::ByteArray& message);

        BaseTools::ByteArray encrypt(const BaseTools::ByteArray& message, int threadCount);
        /**
         * Функция для расшифровки сообщения
         * @param message - сообщение, которое трубется расшифровать
         * @return расшифрованное сообщение
         */
        BaseTools::ByteArray decrypt(const BaseTools::ByteArray& message);
    private:
        std::unique_ptr<Impl_Cryptographer> pImpl;
    };

} // namespace Namespace



#endif //CRYPTOGRAPHICLIBRARY_CRYPTOGRAPHER_H
