#include "HibeGS.h"
#include <gtest/gtest.h>
#include "relic_api.h"
#include "forwardsec.h"
#include <cereal/archives/binary.hpp>
#include <sstream>
#include <math.h>
using namespace relicxx;
using namespace std;
namespace forwardsec
{
char buffer[3];
char *inttohex(int a)
{
    if (a / 16 < 10)
        buffer[0] = a / 16 + '0';
    else
        buffer[0] = a / 16 - 10 + 'a';
    if (a % 16 < 10)
        buffer[1] = a % 16 + '0';
    else
        buffer[1] = a % 16 - 10 + 'a';
    buffer[2] = '\0';
    return buffer;
}

TEST(GroupSetup, test)
{
    //init relic
    relicResourceHandle relic;

    PairingGroup group;
    relicxx::ZR zr = group.randomZR();
    cout << zr << endl;
    uint8_t bin[RELIC_BN_BITS / 8 + 1];

    relicxx::ZR z2;
    int len = CEIL(RELIC_BN_BITS, 8);
    bn_write_bin(bin, len, zr.z);
    for (int i = 0; i < len; i++)
        cout << bin[i];
    cout << endl;
    //bin to str
    string str = "";
    for (int i = 96; i < len; i++)
    {
        int m = atoi(to_string((unsigned int)bin[i]).c_str());
        const char *a = inttohex(m);
        str += a;
    }
    cout << endl;
    cout << str << endl;
    cout << str.length() << " " << len << endl;

    //str to bin
    uint8_t bin2[len];
    for (int i = 0; i < 96; i++)
        bin2[i] = '\0';
    for (int i = 0; i < str.length(); i += 2)
    {
        std::string pair = str.substr(i, 2);
        cout << pair;
        bin2[i / 2+96] = ::strtol(pair.c_str(), 0, 16);
    }
    cout << endl;

    bn_read_bin(z2.z, bin2, len);
    cout << z2;
    //cout << z2 << endl;
    /* char *str = "141801544464023546";
    char *str2 = "11347850211810585423";
    char *str3 = "1820789979809844439";
    char *str4 = "8157286973082078327";
    char *str5 = "13637883117889657169";
    char *str6 = "";
    string s="0xb003200760dd00bd000003b9f70009007c099af200eb4f420f3031400840d1e2ebd00a67c3a490b0007c6c000c9d2477a2000000000df0000c20147700e284af06f50c22b6094e80081d10f90d1b95400006c0007700ce77f780d1ecd2f90";
    relicxx::G2 g;
    int len = FP_BYTES;
    

    fp_read_str(g.g->x[0], str, len, BASE);
    str += len;
    fp_read_str(g.g->x[1], str2, len, BASE);
    str += len;
    fp_read_str(g.g->y[0], str3, len, BASE);
    str += len;
    fp_read_str(g.g->y[1], str4, len, BASE);
    str += len;
    fp_read_str(g.g->z[0], str5, len, BASE);
    str += len;
    fp_read_str(g.g->z[1], str6, len, BASE);
    g.isInit = true;
    cout <<"g.gx1:"<<*g.g->x[0]<<endl;
    cout <<"g:"<<g<<endl;
    cout<<s; */

    /* relicxx::G2 g = group.randomG2();
    cout << *g.g->x[0] << endl;
    cout << *g.g->x[1] << endl;
    cout << *g.g->y[0] << endl;
    cout << *g.g->y[1] << endl;
    cout << *g.g->z[0] << endl;
    cout << *g.g->z[1] << endl;
    cout << g.g->norm<<endl; 
    cout<<g; */

    /* relicxx::G2 g = group.randomG2();
    relicxx::G2 g2;
    relicxx::G2 g3;
    int len = 4 * FP_BYTES + 1;
    uint8_t bin[len];
    int l;
    l = g2_size_bin(g.g, 1);
    g2_write_bin(bin, l, g.g, 1);
    cout << "g:" << g;

    g2_read_bin(g2.g, bin, l);
    cout << "g2:" << g2;
    if (g2_cmp(g.g, g2.g) == CMP_EQ)
        cout << "eq" << endl;

    //bin to str
    string str = "";

    for (int i = 0; i < len; i++)
    {
        int m = atoi(to_string((unsigned int)bin[i]).c_str());
        const char *a = inttohex(m);
        str += a;
    }
    for (int i = str.length() / 2; i < len; i++)
        cout << (unsigned int)bin[i];
    cout << endl;
    cout << str << endl;
    cout << str.length() << " " << len << endl;
    //str to bin
    uint8_t bin2[len];

    for (int i = 0; i < str.length(); i += 2)
    {
        std::string pair = str.substr(i, 2);
        cout << pair;
        bin2[i / 2] = ::strtol(pair.c_str(), 0, 16);
    }
    for (int i = 0; i < len; i++)
        if (bin[i] == bin2[i])
            cout << "1";
    cout << len;
    cout << endl;
    g2_read_bin(g3.g, bin2, l);
    cout << "g3:" << g3;
    if (g2_cmp(g.g, g3.g) == CMP_EQ)
        cout << "eq2"; */

    /* uint8_t bin2[4 * FP_BYTES + 1];
    ep2_set_infty(g.g);
    l = ep2_size_bin(g.g, 1);
    ep2_write_bin(bin2, l, g.g, 1);
    ep2_read_bin(g2.g, bin2, l);
    if (ep2_cmp(g.g, g2.g)==CMP_EQ)
        cout << "eq2";

   
    ep2_t a, b;
    uint8_t bin3[4 * FP_BYTES + 1];
    ep2_set_infty(a);
    l = ep2_size_bin(a, 1);
    ep2_write_bin(bin3, l, a, 1);
    ep2_read_bin(b, bin3, l);
    if (ep2_cmp(a, b)==CMP_EQ)
        cout << "eq3"; */
    /* relicxx::G2 g = group.randomG2();
    cout<<g<<endl;
    cout << g.g->x << endl;
    cout << g.g->y << endl;
    cout << g.g->z << endl;
    cout << g.g->norm << endl;
    g.getBytes();  */

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
