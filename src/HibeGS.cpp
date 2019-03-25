/*
 * @Author: wxmsite
 * @LastEditors: wxmsite
 * @Description: 
 * @Date: 2019-03-17 15:15:09
 * @LastEditTime: 2019-03-25 08:44:09
 */
#include "HibeGS.h"
namespace forwardsec{

using namespace relicxx;
void  HibeGS::setup(MasterPublicKey& mpk, G2& msk) const
{   
    const unsigned int l = 4;
    ZR alpha = group.randomZR();
    mpk.g = group.randomG1();
    mpk.g2 = group.randomG2();
    mpk.hibeg1 = group.exp(mpk.g, alpha);
    //we setup four level HIBE here,the first level is Group identity,the second level is user identity
    //the third level is the signed message,the last level is a random identity
    mpk.l = 4;
    for (unsigned int i = 0; i <= l; i++)
    {
        ZR h = group.randomZR();
       mpk.hG2.push_back(group.exp(mpk.g2, h));
    }
    mpk.n = group.randomGT();
    msk = group.exp(mpk.g2, alpha);
    return;
}

void HibeGS::groupSetup(const std::string& GroupID ,const G2& msk,GroupSecretKey& gsk,const MasterPublicKey& mpk){
   
    const ZR e = group.hashListToZR(GroupID);
    const ZR r1 = group.randomZR();
    gsk.a0 = group.exp(group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),e)),r1);
    gsk.a0 = group.mul(msk,gsk.a0);
    gsk.a2 = group.exp(mpk.hG2.at(2),r1);
    gsk.a3 = group.exp(mpk.hG2.at(3),r1);;
    gsk.a4 = group.exp(mpk.hG2.at(4),r1);
    gsk.a5 = group.exp(mpk.g,r1);
}
bool HibeGS::join(const string& GroupID,const string UserID){
    GroupSecretKey gsk;
    MasterPublicKey mpk(getMpk());
    relicxx::G2 msk(getMsk());

    return true;
}
void HibeGS::join(const string& GroupID,const string& UserID,const GroupSecretKey& gsk,UserSecretKey& usk,const MasterPublicKey& mpk){
    
    const ZR GUserID = group.hashListToZR(UserID);
    const ZR GGroupID = group.hashListToZR(GroupID);
    const ZR r2 = group.randomZR();

    relicxx::G2 res=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),GGroupID));
    res=group.exp(group.mul(res,group.exp(mpk.hG2.at(2),GUserID)),r2);
   usk.b0=group.mul(gsk.a0,group.exp(gsk.a2,GUserID));
   usk.b0=group.mul(usk.b0,res);
   usk.b3=group.mul(gsk.a3,group.exp(mpk.hG2.at(3),r2));
   usk.b4=group.mul(gsk.a4,group.exp(mpk.hG2.at(4),r2));
   usk.b5=group.mul(gsk.a5,group.exp(mpk.g,r2));
}
void HibeGS::sign(const ZR& m,const UserSecretKey& usk,Sig& sig,const MasterPublicKey& mpk){
    const ZR GUserID=group.hashListToZR(getUserID());
    const ZR GGroupID = group.hashListToZR(getGroupID());
    //G(UserID),G(r4),k are public
    const ZR r3 = group.randomZR();
    //r4 use to blind identity
    const ZR r4 = group.randomZR();
    //user to encrypt identity to the group manager
    const ZR k = group.randomZR();
    relicxx::G2 res=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),GGroupID));
    res=group.mul(res,group.exp(mpk.hG2.at(2),GUserID));
    res=group.mul(res,group.exp(mpk.hG2.at(3),m));
    res=group.exp(group.mul(res,group.exp(mpk.hG2.at(4),r4)),r3);
    sig.c0=group.mul(usk.b0,group.exp(usk.b3,m));
    sig.c0=group.mul(group.mul(sig.c0,group.exp(usk.b4,r4)),res);
    sig.c5=group.mul(usk.b5,group.exp(mpk.g,r3));

    sig.c6=group.mul(group.exp(mpk.hG2.at(2),GUserID),group.exp(mpk.hG2.at(4),r4));
    sig.e1=group.exp(mpk.g,k);
    sig.e2=group.exp(group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),GGroupID)),k);
    
    sig.e3=group.exp(group.pair(mpk.g2, mpk.hibeg1), k);
    sig.e3=group.mul(sig.e3,group.exp(mpk.n,GUserID));
    sig.r4=r4;
    sig.k=k;

}
bool HibeGS::verify(const ZR& m,const Sig& sig,const string& GroupID,const MasterPublicKey& mpk){
    const ZR GGroupID = group.hashListToZR(getGroupID());
    const ZR GUserID=group.hashListToZR(getUserID());
    const ZR y=sig.r4;
    const ZR t=group.randomZR();
    const GT M=group.randomGT(); 
    const ZR k=sig.k;
    relicxx::G1 d1=group.exp(mpk.g,t);
    relicxx::G2 d2=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),GGroupID));
    d2=group.exp(group.mul(d2,group.mul(group.exp(mpk.hG2.at(3),m),sig.c6)),t);
    relicxx::GT delta3=group.mul(M,group.exp(group.pair(mpk.hibeg1, mpk.g2), t));
    relicxx::GT result=group.mul(delta3,group.div(group.pair(sig.c5,d2),group.pair(d1,sig.c0)));
    
    return M==result&&
    sig.c6==group.mul(group.exp(mpk.hG2.at(2),GUserID),group.exp(mpk.hG2.at(4),y))&&
    sig.e1==group.exp(mpk.g,k)&&
    sig.e2==group.exp(group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),GGroupID)),k)&&
    sig.e3==group.mul(group.exp(mpk.n,GUserID),group.exp(group.pair(mpk.hibeg1, mpk.g2),k));
    
}
ZR HibeGS::open(const MasterPublicKey& mpk,const GroupSecretKey& gsk,const Sig& sig){
    const ZR GUserID=group.hashListToZR(getUserID());
    relicxx::GT t=group.exp(group.pair(mpk.hibeg1,mpk.g2),sig.k);
    //goes through all user identifiers here
    if(sig.e3==group.mul(group.exp(mpk.n,GUserID),t))
        return GUserID;
    else
        return group.randomZR();
}
string HibeGS::getGroupID(){
    return "science";
}
string HibeGS::getUserID(){
    return "www";
}
MasterPublicKey HibeGS::getMpk(){
    return  MasterPublicKey();
}
relicxx::G2 HibeGS::getMsk(){
    return group.randomG2();
}
}
