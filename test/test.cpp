#include "HibeGS.h"
#include <gtest/gtest.h>
#include "relic_api.h"
#include "forwardsec.h"
#include <cereal/archives/binary.hpp>
#include <sstream>
using namespace relicxx;
using namespace std;
namespace forwardsec
{
TEST(GroupSetup, test)
{
    //init relic
    relicResourceHandle relic;
    relicxx::ZR zr("123");
    //cout << zr << endl;

    std::vector<uint8_t> data;
    string str = "0xf900f00000c0293cb100021401003f07aae0290d9210299b0dd95a0d9a0000d9c021000d0000fbb09f5f29b800bca22da040c8530210d0097f0530aed6007c000a0d5a0000f60969dbcae96d4da1190260d0b30bb335905f0bf0bc00db005e3310dbc";
    //string str = "0x11212125sgjwgiw4io24";
    bytes b(str.begin(),str.end());
    
    
   
    relicxx::G2 g(data);
    //没有缓冲区bug
    cout << g;
    /*  
    relicxx::G2 g;
    std::stringstream ss("/home/www/a.bin");
    {
    cereal::BinaryOutputArchive oarchive(ss);
    oarchive(CEREAL_NVP(str));
    g.save(oarchive);
    }
   
    
    cout<<g;  */
    /* HibeGS *hibegs = new HibeGS();
    MasterPublicKey mpk;
    relicxx::G2 msk;
    GroupSecretKey gsk;
    UserSecretKey usk;
    PairingGroup group;
    Sig sig;
    const relicxx::ZR m = group.randomZR();
    hibegs->setup(mpk, msk);
    hibegs->groupSetup("science", msk, gsk, mpk);
    hibegs->join("science", "www", gsk, usk, mpk);
    hibegs->sign(m, usk, sig, mpk);
    EXPECT_TRUE(hibegs->verify(m, sig, "science", mpk));
    EXPECT_TRUE(hibegs->open(mpk, gsk, sig) == group.hashListToZR("www")); */
}
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace forwardsec
