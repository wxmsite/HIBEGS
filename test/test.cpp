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
    PairingGroup group;

    /* relicxx::G2 g = group.randomG2();
    cout<<g<<endl;
    cout << g.g->x << endl;
    cout << g.g->y << endl;
    cout << g.g->z << endl;
    cout << g.g->norm << endl;
    g.getBytes();  */
    ep2_t a, b;
    int l;
    uint8_t bin[4 * FP_BYTES + 1];
    ep2_new(a);
    for (int j = 0; j < 2; j++)
    {
        ep2_set_infty(a);
        l = ep2_size_bin(a, j);
        ep2_write_bin(bin, l, a, j);
        ep2_read_bin(b, bin, l);
        if (ep2_cmp(a, b))
            cout << 123;
        ep2_rand(a);
        l = ep2_size_bin(a, j);
        ep2_write_bin(bin, l, a, j);
        ep2_read_bin(b, bin, l);
        if (ep2_cmp(a, b))
            cout << 2;
        ep2_rand(a);
        ep2_dbl(a, a);
        l = ep2_size_bin(a, j);
        ep2_norm(a, a);
        ep2_write_bin(bin, l, a, j);
        ep2_read_bin(b, bin, l);
        if (ep2_cmp(a, b))
            cout << 3;
    }

    /*   std::vector<uint8_t> data;
    string str = "f900f00000c0293cb100021401003f07aae0290d9210299b0dd95a0d9a0000d9c021000d0000fbb09f5f29b800bca22da040c8530210d0097f0530aed6007c000a0d5a0000f60969dbcae96d4da1190260d0b30bb335905f0bf0bc00db005e3310dbc";
    //string str = "0x11212125sgjwgiw4io24";
    //bytes b(str.begin(), str.end());

    data.reserve(str.size());
    for (int i = 0; i < str.length(); i += 2)
    {
        std::string pair = str.substr(i, 2);
        data.push_back(::strtol(pair.c_str(), 0, 16));
    }

    relicxx::G2 g(data);

    cout << g;
 */
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
