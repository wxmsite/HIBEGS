/*
 * @Author: wxmsite
 * @LastEditors: wxmsite
 * @Description: 
 * @Date: 2019-03-17 15:15:09
 * @LastEditTime: 2019-03-21 11:01:43
 */
#include "HibeGS.h"
namespace forwardsec{
using namespace std;
using namespace relicxx;
void  HibeGS::Setup(MasterPublicKey& mpk, G2& msk) const
{   
    const unsigned int l = 4;
    ZR alpha = group.randomZR();
    mpk.gG1 = group.randomG1();
    mpk.gG2 = group.randomG2();
    mpk.hibeg1 = group.exp(mpk.gG2, alpha);
    mpk.l = 4;
    const ZR r = group.randomZR();
    mpk.g2G1 = group.exp(mpk.gG1, r);
    mpk.g2G2 = group.exp(mpk.gG2, r);
    const ZR r1 = group.randomZR();
    for (unsigned int i = 0; i <= l; i++)
    {
        ZR h = group.randomZR();
       mpk.hG1.push_back(group.exp(mpk.gG1, h));
       mpk.hG2.push_back(group.exp(mpk.gG2, h));
    }
    mpk.n = group.randomZR();
    msk = group.exp(mpk.g2G2, alpha);

    return;
}

void HibeGS::GroupSetup(const char* GourpID,const G2& msk,GroupSecretKey& gsk,const MasterPublicKey& mpk){
    //将字符串GroupID转为e,e=Distill(GroupID)
    int e = 123;
    const ZR r1 = group.randomZR();
    gsk.a0 = group.exp(mpk.hG2.at(1),e);
    gsk.a0 = group.exp(group.mul(mpk.hG2.at(0),gsk.a0),r1);
    gsk.a0 = group.mul(gsk.a0,msk);
    gsk.a2 = group.exp(mpk.hG2.at(2),r1);
    gsk.a3 = group.exp(mpk.hG2.at(3),r1);;
    gsk.a4 = group.exp(mpk.hG2.at(4),r1);
    gsk.a5 = group.exp(mpk.gG2,r1);
}
void HibeGS::Join(const char*GroupID,const char* UserID,const GroupSecretKey& gsk,UserSecretKey& usk,const MasterPublicKey& mpk){
    //此处将(groupID,userID)转为e,e=Distill((GroupID,UserID),mpk)
    int e = 123;
    const ZR r2 = group.randomZR();
    
   usk.b0=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),getGroupID()));
   usk.b0=group.mul(usk.b0,group.exp(mpk.hG2.at(2),e));
   usk.b0=group.exp(usk.b0,r2);
   usk.b0=group.mul(usk.b0,group.exp(gsk.a2,e));
   usk.b0=group.mul(usk.b0,gsk.a0);   
   usk.b3=group.mul(gsk.a3,group.exp(mpk.hG2.at(3),r2));
   usk.b4=group.mul(gsk.a4,group.exp(mpk.hG2.at(4),r2));
   usk.b5=group.mul(gsk.a5,group.exp(mpk.gG2,r2));
}
void HibeGS::Sign(ZR& m,const UserSecretKey& usk,Sig& sig,const MasterPublicKey& mpk,const GroupSecretKey& gsk){
    const ZR r3 = group.randomZR();
    //random idetity r4 from IdSp,IdSp is a set of basic identities IdSp ⊆ {0, 1}*，r4 use to blind identity
    const ZR r4 = group.randomZR();
    //user to encrypt identity to the group manager
    const ZR k = group.randomZR();
    sig.c0=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),getGroupID()));
    sig.c0=group.mul(sig.c0,group.exp(mpk.hG2.at(2),getUserID()));
    sig.c0=group.mul(sig.c0,group.exp(mpk.hG2.at(3),m));
    sig.c0=group.exp(group.mul(sig.c0,group.exp(mpk.hG2.at(4),r4)),r3);
    sig.c0=group.mul(sig.c0,usk.b0);
    sig.c0=group.mul(sig.c0,group.exp(mpk.hG2.at(3),m));
    sig.c0=group.mul(sig.c0,group.exp(gsk.a4,r4));
    sig.c5=group.mul(usk.b5,group.exp(mpk.gG2,r3));
    sig.c6=group.mul(group.exp(mpk.hG2.at(2),getUserID()),group.exp(mpk.hG2.at(4),r4));
    

}
ZR HibeGS::getGroupID(){
    return group.randomZR();
}
ZR HibeGS::getUserID(){
    return ;
}
}
