/*
 * @Author: wxmsite
 * @LastEditors: wxmsite
 * @Description: 
 * @Date: 2019-03-17 14:59:48
 * @LastEditTime: 2019-03-24 19:13:17
 */
#include "relic_api.h"
#include "forwardsec.h"
using namespace std;
namespace forwardsec{
class GMPfse;
class HibeGS;

class MasterPublicKey:  public virtual  baseKey{
	
public:
  MasterPublicKey(){};
	~MasterPublicKey(){};
 	friend bool operator==(const MasterPublicKey& x, const MasterPublicKey& y){
		return  ((baseKey)x == (baseKey)y &&
				x.l == y.l && x.hibeg1 == y.hibeg1&& x.hG2 == y.hG2&&x.n==y.n);
	}
	friend bool operator!=(const MasterPublicKey& x, const MasterPublicKey& y){
		return !(x==y);
	}

protected:

	unsigned int l;
	relicxx::G1 hibeg1;
	vector<relicxx::G2> hG2;
	relicxx::GT n;
	template <class Archive>
	  void serialize( Archive & ar )
	{
		ar(::cereal::virtual_base_class<baseKey>(this),
				l,hibeg1,hG2,n);
	}
	friend class ::cereal::access;
	friend class GMPfse;
	friend class HibeGS;
};

class GroupSecretKey{
public:

	friend bool operator==(const GroupSecretKey& x, const GroupSecretKey& y){
		return  (x.a0 == y.a0 && x.a2==y.a2&&x.a3==y.a3&&x.a4==y.a4&&x.a5==y.a5);
	}
	friend bool operator!=(const GroupSecretKey& x, const GroupSecretKey& y){
		return !(x==y);
	}
	void neuter();
protected:

	relicxx::G2 a0;
	relicxx::G2 a2;
	relicxx::G2 a3;
	relicxx::G2 a4;
	relicxx::G1 a5;
	template <class Archive>
	  void serialize( Archive & ar )
	{
		ar(a0,a2,a3,a4,a5);
	}
	friend class ::cereal::access;
	friend class GMPfse;
	friend class HibeGS;
};

class UserSecretKey{
public:

	friend bool operator==(const UserSecretKey& x, const UserSecretKey& y){
		return  (x.b0 == y.b0 && x.b3==y.b3&&x.b4==y.b4&&x.b5==y.b5);
	}
	friend bool operator!=(const UserSecretKey& x, const UserSecretKey& y){
		return !(x==y);
	}
	void neuter();
protected:
	relicxx::G2 b0;
	relicxx::G2 b3;
	relicxx::G2 b4;
	relicxx::G1 b5;
	template <class Archive>
	  void serialize( Archive & ar )
	{
		ar(b0,b3,b4,b5);
	}
	friend class ::cereal::access;
	friend class GMPfse;
	friend class HibeGS;
};
/**
 * @description: 
 * @param {type} 
 * @return: 
 */
class Sig{
public:

	friend bool operator==(const Sig& x, const Sig& y){
		return  (x.c0 == y.c0 && x.c5==y.c5&&x.c6==y.c6&&x.e1==y.e1&&x.e2==y.e2&&x.e3==y.e3&&
		x.r4==y.r4&&x.k==y.k);
	}
	friend bool operator!=(const Sig& x, const Sig& y){
		return !(x==y);
	}
	void neuter();
protected:
	relicxx::G2 c0;
	relicxx::G1 c5;
	relicxx::G2 c6;
	relicxx::G1 e1;
	relicxx::G2 e2;
	relicxx::GT e3;
	relicxx::ZR r4;
	relicxx::ZR k;
	template <class Archive>
	  void serialize( Archive & ar )
	{
		ar(c0,c5,c6,e1,e2,e3);
	}
	friend class ::cereal::access;
	friend class GMPfse;
	friend class HibeGS;
};

class HibeGS{
  public:
	relicxx::PairingGroup group;
	HibeGS(){};
	~HibeGS() {};
 /**
  * @description: The trusted authority generates its mpk and msk
  * @param {
	* mpk, master public key,
	*  msk,master secret key
	* } 
  * @return: 
  */
	void setup(MasterPublicKey& mpk, relicxx::G2& msk) const;
  
	/**
  * @description: use mpk,msk and GroupID to generate a group with gsk(a0,a2,a3,a4,a5)
  * @param {
	* GroupID:group id,
	*  msk:master secret  key,
	*  gsk:group secret key
	*  mpk:master public key
	* } 
  * @return: 
  */
	void groupSetup(const string& GroupID ,const relicxx::G2& msk, GroupSecretKey& gsk ,const MasterPublicKey& mpk);
	/**
  * @description: 
  * @param {
	* UserID:user id,
	* usk:user secret key
	} 
  * @return: 
  */
  bool join(const string& GroupID,const string UserID);
	void join(const string& GroupID,const string& UserID,const GroupSecretKey& gsk,UserSecretKey& usk,const MasterPublicKey& mpk);
	/**
  * @description: 
  * @param {
	* m:the message to be signed,
	* usk:user secret key
	* sig: the signature
	* } 
  * @return: 
  */
 void sign(const relicxx::ZR& m,const UserSecretKey& usk,Sig& sig,const MasterPublicKey& mpk);
 /**
  * @description: 
  * @param {type} 
  * @return: 
  */
 bool verify(const relicxx::ZR&m,const Sig& sig,const string& GroupID,const MasterPublicKey& mpk);
 /**
  * @description: The Group Manager goes through all user identifiers and find the one who signed m
  * @param {type} 
  * @return: 
  */
 relicxx::ZR open(const MasterPublicKey& mpk,const GroupSecretKey& gsk,const Sig& sig);
/**
 * @description: 
 * @param {null} 
 * @return: 
 */
string getGroupID();
 /**
  * @description: 
  * @param {null} 
  * @return: 
  */
 string getUserID();

vector<string> getGroupMember(string GroupID);

MasterPublicKey getMpk();

relicxx::G2 getMsk();

};
}