/*
 * @Author: wxmsite
 * @LastEditors: wxmsite
 * @Description: 
 * @Date: 2019-03-17 15:15:09
 * @LastEditTime: 2019-03-22 13:55:07
 */
#include "HibeGS.h"
namespace forwardsec{
using namespace std;
using namespace relicxx;
void  HibeGS::setup(MasterPublicKey& mpk, G2& msk) const
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
    mpk.n = group.randomGT();
    msk = group.exp(mpk.g2G2, alpha);
    return;
}

void HibeGS::groupSetup(const std::string GroupID ,const G2& msk,GroupSecretKey& gsk,const MasterPublicKey& mpk){
    //将字符串GroupID转为e,e=Distill(GroupID)
    const ZR e = group.hashListToZR(GroupID);
    const ZR r1 = group.randomZR();
    gsk.a0 = group.exp(mpk.hG2.at(1),e);
    gsk.a0 = group.exp(group.mul(mpk.hG2.at(0),gsk.a0),r1);
    gsk.a0 = group.mul(gsk.a0,msk);
    gsk.a2 = group.exp(mpk.hG2.at(2),r1);
    gsk.a3 = group.exp(mpk.hG2.at(3),r1);;
    gsk.a4 = group.exp(mpk.hG2.at(4),r1);
    gsk.a5 = group.exp(mpk.gG2,r1);
}
void HibeGS::join(const char*GroupID,const char* UserID,const GroupSecretKey& gsk,UserSecretKey& usk,const MasterPublicKey& mpk){
    //此处将(groupID,userID)转为e,e=Distill((GroupID,UserID),mpk)
    const ZR e = group.hashListToZR(UserID);
    const ZR r2 = group.randomZR();
    
   usk.b0=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),e));
   usk.b0=group.mul(usk.b0,group.exp(mpk.hG2.at(2),e));
   usk.b0=group.exp(usk.b0,r2);
   usk.b0=group.mul(usk.b0,group.exp(gsk.a2,e));
   usk.b0=group.mul(usk.b0,gsk.a0);   
   usk.b3=group.mul(gsk.a3,group.exp(mpk.hG2.at(3),r2));
   usk.b4=group.mul(gsk.a4,group.exp(mpk.hG2.at(4),r2));
   usk.b5=group.mul(gsk.a5,group.exp(mpk.gG2,r2));
}
void HibeGS::sign(const ZR& m,const UserSecretKey& usk,Sig& sig,const MasterPublicKey& mpk,const GroupSecretKey& gsk){
    const ZR GUserID=group.hashListToZR(getUserID());
    const ZR GGroupID = group.hashListToZR(getGroupID());
    //G(UserID),G(r4),k are public
    const ZR r3 = group.randomZR();
    //random idetity r4 from IdSp,IdSp is a set of basic identities IdSp ⊆ {0, 1}*，r4 use to blind identity
    const ZR r4 = group.randomZR();
    //user to encrypt identity to the group manager
    const ZR k = group.randomZR();
    sig.c0=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),GGroupID));
    sig.c0=group.mul(sig.c0,group.exp(mpk.hG2.at(2),GUserID));
    sig.c0=group.mul(sig.c0,group.exp(mpk.hG2.at(3),m));
    sig.c0=group.exp(group.mul(sig.c0,group.exp(mpk.hG2.at(4),r4)),r3);
    sig.c0=group.mul(sig.c0,usk.b0);
    sig.c0=group.mul(sig.c0,group.exp(mpk.hG2.at(3),m));
    sig.c0=group.mul(sig.c0,group.exp(gsk.a4,r4));
    sig.c5=group.mul(usk.b5,group.exp(mpk.gG2,r3));
    sig.c6=group.mul(group.exp(mpk.hG1.at(2),GUserID),group.exp(mpk.hG1.at(4),r4));
    sig.e1=group.exp(mpk.gG1,k);
    sig.e2=group.exp(group.mul(mpk.hG1.at(0),group.exp(mpk.hG1.at(1),GGroupID)),k);
    
    sig.e3=group.exp(group.pair(mpk.g2G1, mpk.hibeg1), k);
    sig.e3=group.mul(sig.e3,group.exp(mpk.n,GUserID));
    sig.r4=r4;
    sig.k=k;

}
bool HibeGS::verify(const ZR& m,const Sig& sig,const char* GroupID,const MasterPublicKey& mpk){
    const ZR GGroupID = group.hashListToZR(getGroupID());
    const ZR GUserID=group.hashListToZR(getUserID());
    const ZR y=sig.r4;
    const ZR t=group.randomZR();
    const GT M=group.randomGT(); 
    const ZR k=sig.k;
    relicxx::G1 d1=group.exp(mpk.gG1,t);
    relicxx::G1 d2=group.mul(mpk.hG1.at(0),group.exp(mpk.hG1.at(1),GGroupID));
    d2=group.mul(d2,group.mul(group.exp(mpk.hG1.at(3),m),sig.c6));
    relicxx::GT delta3=group.mul(M,group.exp(group.pair(mpk.g2G1, mpk.hibeg1), t));
    relicxx::GT result1=group.mul(delta3,group.div(group.pair(d2,sig.c5),group.pair(d1,sig.c0)));
    
    return M==result1&&
    sig.c6==group.mul(group.exp(mpk.hG1.at(2),GUserID),group.exp(mpk.hG1.at(4),y))&&
    sig.e1==group.exp(mpk.gG1,k)&&
    sig.e2==group.exp(group.mul(mpk.hG1.at(0),group.exp(mpk.hG1.at(1),GGroupID)),k)&&
    sig.e3==group.mul(group.exp(mpk.n,GUserID),group.exp(group.pair(mpk.g2G1, mpk.hibeg1),k));
}
ZR HibeGS::open(const MasterPublicKey& mpk,const GroupSecretKey& gsk,const Sig& sig){
    const ZR GUserID=group.hashListToZR(getUserID());
    relicxx::GT t=group.exp(group.pair(mpk.g2G1,mpk.hibeg1),sig.k);
    
    if(sig.e3==group.mul(group.exp(mpk.n,GUserID),t))
        return GUserID;
}
string HibeGS::getGroupID(){
    return "science";
}
string HibeGS::getUserID(){
    return "www";
}

}
