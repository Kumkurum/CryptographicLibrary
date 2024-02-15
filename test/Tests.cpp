//
// Created by andrey on 05.10.23.
//
#include "Tests.h"
#include "../include/CryptographicLibrary/Cryptographer.h"
using namespace BaseTools;
using namespace Lucifer;

TEST(Test_1, SECOND) {
    BaseTools::ByteArray msg{"eternity", 8};
    Lucifer::Cryptographer lucifer{ByteArray{"alekos", 6}};

    auto cryptMsg = lucifer.encrypt(msg);
    auto decrypt = lucifer.decrypt(cryptMsg);
    EXPECT_STREQ(msg.dataChar(), decrypt.dataChar());
    EXPECT_TRUE(true);
}

TEST(Test_2, SECOND) {
    BaseTools::ByteArray msg{"Hellow world!", 13};
    Lucifer::Cryptographer lucifer{ByteArray{"kumkurum", 8}};

    auto cryptMsg = lucifer.encrypt(msg);
    auto decrypt = lucifer.decrypt(cryptMsg);
    EXPECT_STREQ(msg.dataChar(), decrypt.dataChar());
    EXPECT_TRUE(true);
}
TEST(Test_3, SECOND) {
    BaseTools::ByteArray msg{"eternity", 8};
    Lucifer::Cryptographer lucifer{ByteArray{"kumkurum", 8}};

    auto cryptMsg = lucifer.encrypt(ByteArray{"eternity", 8});
    auto decrypt = lucifer.decrypt(cryptMsg);
    EXPECT_STREQ(ByteArray("eternity", 8).dataChar(), decrypt.dataChar());
    EXPECT_TRUE(true);
}

TEST(Test_4, Two_Thread) {
    BaseTools::ByteArray msg{"ассказ у нас пойдет в особенности о хоббитах, и любознательный читатель многое узнает об их нравах и кое-что из их истории. Самых любознательных отсылаем к повести под названием «Хоббит», где пересказаны начальные главы Алой Книги Западных Пределов, которые написал Бильбо Торбинс, впервые прославивший свой народец в большом мире. Главы эти носят общий подзаголовок «Туда и обратно», потому что повествуют о странствии Бильбо на восток и возвращении домой. Как раз по милости Бильбо хоббиты и угодили в самую лавину грозных событий, о которых нам предстоит поведать.\n"
                             "Многие, однако, и вообще про хоббитов ничего не знают, а хотели бы знать – но не у всех же есть под рукой книга «Хоббит». Вот и прочтите, если угодно, начальные сведения о хоббитах, а заодно и краткий пересказ приключений Бильбо.\n"
                             "Хоббиты – неприметный, но очень древний народец; раньше их было куда больше, чем нынче: они любят тишину и покой, тучную пашню и цветущие луга, а сейчас в мире стало что-то очень шумно и довольно тесно. Умелые и сноровистые, хоббиты, однако, терпеть не могли – не могут и поныне – устройств сложнее кузнечных мехов, водяной мельницы и прялки."};
    Lucifer::Cryptographer lucifer{ByteArray{"kumkurum", 8}};

    auto cryptMsg = lucifer.encrypt(msg, 4);
//    auto decrypt = lucifer.decrypt(cryptMsg);
//    EXPECT_STREQ(ByteArray("eternity", 8).dataChar(), decrypt.dataChar());
//    EXPECT_TRUE(true);
}