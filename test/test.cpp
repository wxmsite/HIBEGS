#include"HibeGS.h"
#include <gtest/gtest.h>  
#include "relic_api.h"
#include "forwardsec.h"
using namespace relicxx;
using namespace std;
namespace forwardsec{
TEST(GroupSetup,test){
    //初始化relic
    relicResourceHandle relic;
    HibeGS *hibegs=new HibeGS();
    MasterPublicKey mpk;
    relicxx::G2 msk;
    GroupSecretKey gsk;
    UserSecretKey usk;
    PairingGroup group;
    Sig sig;
    const relicxx::ZR m=group.randomZR();
    hibegs->setup(mpk,msk);
    hibegs->groupSetup("science",msk,gsk,mpk);
    hibegs->join("science","www",gsk,usk,mpk);
    hibegs->sign(m,usk,sig,mpk,gsk);
    EXPECT_TRUE(hibegs->verify(m,sig,"science",mpk));
    EXPECT_TRUE(hibegs->open(mpk,gsk,sig)==group.hashListToZR("www"));
    
}
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
}
