/*
 * @Author: wxmsite
 * @LastEditors: wxmsite
 * @Description: 
 * @Date: 2019-03-17 15:15:09
 * @LastEditTime: 2019-03-26 10:42:45
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

bool HibeGS::groupSetup(const string& groupID){
    //判断群组是否存在等业务逻辑
    //如果存在,获取msk
    relicxx::G2 msk(getMsk());
    GroupSecretKey gsk;
    MasterPublicKey mpk;
    groupSetup(groupID,msk,gsk,mpk);
    //返回gsk给group manager，mpk有9部分，可以考虑分给九个人，另说

    return true;
}
void HibeGS::groupSetup(const std::string& groupID ,const G2& msk,GroupSecretKey& gsk,const MasterPublicKey& mpk){
   
    const ZR e = group.hashListToZR(groupID);
    const ZR r1 = group.randomZR();
    gsk.a0 = group.exp(group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),e)),r1);
    gsk.a0 = group.mul(msk,gsk.a0);
    gsk.a2 = group.exp(mpk.hG2.at(2),r1);
    gsk.a3 = group.exp(mpk.hG2.at(3),r1);;
    gsk.a4 = group.exp(mpk.hG2.at(4),r1);
    gsk.a5 = group.exp(mpk.g,r1);
}

bool HibeGS::join(const string& groupID,const string userID){
    GroupSecretKey gsk;
    MasterPublicKey mpk(getMpk());
    UserSecretKey usk;
    //此处添加是否已经加入该群组或者该群组是否存在等业务逻辑
    join(groupID,userID,gsk,usk,mpk);
    //返回usk给用户（审稿人）
    return true;
}

void HibeGS::join(const string& groupID,const string& userID,const GroupSecretKey& gsk,UserSecretKey& usk,const MasterPublicKey& mpk){
    
    const ZR gUserID = group.hashListToZR(userID);
    const ZR gGroupID = group.hashListToZR(groupID);
    const ZR r2 = group.randomZR();

    relicxx::G2 res=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),gGroupID));
    res=group.exp(group.mul(res,group.exp(mpk.hG2.at(2),gUserID)),r2);
    usk.b0=group.mul(gsk.a0,group.exp(gsk.a2,gUserID));
    usk.b0=group.mul(usk.b0,res);
    usk.b3=group.mul(gsk.a3,group.exp(mpk.hG2.at(3),r2));
    usk.b4=group.mul(gsk.a4,group.exp(mpk.hG2.at(4),r2));
    usk.b5=group.mul(gsk.a5,group.exp(mpk.g,r2));
}

void HibeGS::sign(const string message){
    //单盲双盲问题，提交者和审稿人各自怎么匿名
    const ZR m=group.hashListToZR(message);
    MasterPublicKey mpk(getMpk());
    Sig sig;
    UserSecretKey usk;
    sign(m,usk,sig,mpk);
    //提交签名到区块链

}

void HibeGS::sign(const ZR& m,const UserSecretKey& usk,Sig& sig,const MasterPublicKey& mpk){
    const ZR gUserID=group.hashListToZR(getUserID());
    const ZR gGroupID = group.hashListToZR(getGroupID());
    //G(UserID),G(r4),k are public
    const ZR r3 = group.randomZR();
    //r4 use to blind identity
    const ZR r4 = group.randomZR();
    //user to encrypt identity to the group manager
    const ZR k = group.randomZR();
    relicxx::G2 res=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),gGroupID));
    res=group.mul(res,group.exp(mpk.hG2.at(2),gUserID));
    res=group.mul(res,group.exp(mpk.hG2.at(3),m));
    res=group.exp(group.mul(res,group.exp(mpk.hG2.at(4),r4)),r3);
    sig.c0=group.mul(usk.b0,group.exp(usk.b3,m));
    sig.c0=group.mul(group.mul(sig.c0,group.exp(usk.b4,r4)),res);
    sig.c5=group.mul(usk.b5,group.exp(mpk.g,r3));
 
    sig.c6=group.mul(group.exp(mpk.hG2.at(2),gUserID),group.exp(mpk.hG2.at(4),r4));
    sig.e1=group.exp(mpk.g,k);
    sig.e2=group.exp(group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),gGroupID)),k);
    
    sig.e3=group.exp(group.pair(mpk.g2, mpk.hibeg1), k);
    sig.e3=group.mul(sig.e3,group.exp(mpk.n,gUserID));
    sig.r4=r4;
    sig.k=k;

}
bool HibeGS::verify(const ZR& m,const Sig& sig,const string& groupID,const MasterPublicKey& mpk){
    const ZR gGroupID = group.hashListToZR(getGroupID());
    const ZR gUserID=group.hashListToZR(getUserID());
    const ZR y=sig.r4;
    const ZR t=group.randomZR();
    const GT M=group.randomGT(); 
    const ZR k=sig.k;
    relicxx::G1 d1=group.exp(mpk.g,t);
    relicxx::G2 d2=group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),gGroupID));
    d2=group.exp(group.mul(d2,group.mul(group.exp(mpk.hG2.at(3),m),sig.c6)),t);
    relicxx::GT delta3=group.mul(M,group.exp(group.pair(mpk.hibeg1, mpk.g2), t));
    relicxx::GT result=group.mul(delta3,group.div(group.pair(sig.c5,d2),group.pair(d1,sig.c0)));
    
    return M==result&&
    sig.c6==group.mul(group.exp(mpk.hG2.at(2),gUserID),group.exp(mpk.hG2.at(4),y))&&
    sig.e1==group.exp(mpk.g,k)&&
    sig.e2==group.exp(group.mul(mpk.hG2.at(0),group.exp(mpk.hG2.at(1),gGroupID)),k)&&
    sig.e3==group.mul(group.exp(mpk.n,gUserID),group.exp(group.pair(mpk.hibeg1, mpk.g2),k));
    
}
ZR HibeGS::open(const MasterPublicKey& mpk,const GroupSecretKey& gsk,const Sig& sig){
    const ZR gUserID=group.hashListToZR(getUserID());
    relicxx::GT t=group.exp(group.pair(mpk.hibeg1,mpk.g2),sig.k);
    //goes through all user identifiers here
    if(sig.e3==group.mul(group.exp(mpk.n,gUserID),t))
        return gUserID;
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
    //此处加入信任中心后台获取自己的usk操作
    return group.randomG2();
}
}
