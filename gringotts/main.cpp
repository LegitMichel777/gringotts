#include <iostream>
#include <fstream>
#include <unistd.h>
#include <vector>
#include "argon2.h"
#include "aes.h"
#include "xxhsum.h"
#include <stack>
#include <map>
#include <sstream>
#include <cmath>
#include <set>
#include <thread>
#define SYS 0
#define APPL 0
#define WIN 1
using namespace std;
typedef long long ll;
unsigned char urandom_draw() {
    unsigned char random_value = 0; //Declare value to store data into
    size_t size = sizeof(random_value); //Declare size of data
    ifstream urandom("/dev/urandom", ios::in|ios::binary); //Open stream
    if(urandom) {
        urandom.read(reinterpret_cast<char*>(&random_value), size); //Read from urandom
        if(urandom) {
            return random_value;
        }
        urandom.close(); //close stream
    }
    throw "urandomFailure";
    return 0;
}
unsigned long long urandom_draw_ull() {
    unsigned long long random_value = 0; //Declare value to store data into
    size_t size = sizeof(random_value); //Declare size of data
    ifstream urandom("/dev/urandom", ios::in|ios::binary); //Open stream
    if(urandom) {
        urandom.read(reinterpret_cast<char*>(&random_value), size); //Read from urandom
        if(urandom) {
            return random_value;
        }
        urandom.close(); //close stream
    }
    throw "urandomFailure";
    return 0;
}
string db;
namespace fs = std::__fs::filesystem;
void clc() {
    if (SYS==APPL) system("clear");
    else system("clc");
}
string uchar2hex(unsigned char *toConv,size_t len) {
    string rturn;
    for (ll i=0;i<len;i++) {
        ll num=(toConv[i]&(15<<4))>>4;
        if (num<10) rturn=rturn+(char)(num+'0');
        else rturn=rturn+(char)(num-10+'A');
        num=toConv[i]&15;
        if (num<10) rturn=rturn+(char)(num+'0');
        else rturn=rturn+(char)(num-10+'A');
    }
    return rturn;
}
string safespace(string s,int OS=SYS) {
    string rturn;
    if (OS==APPL) {
        map<char,bool>toEscape;
        toEscape['~']=toEscape['=']=toEscape['[']=toEscape[']']=toEscape['{']=toEscape['}']=toEscape['\\']=toEscape['|']=toEscape[';']=toEscape['\'']=toEscape['"']=toEscape['<']=toEscape['>']=toEscape['?']=toEscape[' ']=toEscape['!']=toEscape['#']=toEscape['%']=toEscape['&']=toEscape['*']=toEscape['(']=toEscape[')']=1;
        stringstream ss;
        for (ll i=0;i<s.length();i++) toEscape[s[i]] ? ss<<"\\"<<s[i] : ss<<s[i];
        rturn=ss.str();
    } else if (OS==WIN) {
        rturn="\""+s+"\"";
        for (ll i=0;i<rturn.size();i++) if (rturn[i]=='/') rturn[i]='\\';
    }
    return rturn;
}
string rdcPth(string pth) {
    while (pth.find("/")!=string::npos) pth=pth.substr(pth.find("/")+1);
    return pth;
}
map<string,string>filnames;
//multimap<string,string>revfnames;
unsigned char *masterpwd;
void doFsave() {
    unsigned char *fnameiv=new unsigned char[16];
    for (ll i=0;i<16;i++) fnameiv[i]=urandom_draw();
    vector<unsigned char *>ivi;
    ivi.push_back(fnameiv);
    string encfdata;
    encfdata=to_string(filnames.size());
    for (map<string,string>::iterator i=filnames.begin();i!=filnames.end();i++) {
        encfdata+="\n"+i->first+"\n"+i->second;
    }
    ll newlen=ceil(encfdata.length()/16.0)*16;
    char *disData=new char[newlen];
    for (ll i=0;i<encfdata.length();i++) disData[i]=encfdata[i];
    for (ll i=encfdata.length();i<newlen;i++) disData[i]=0;
    aes_encrypt(reinterpret_cast<unsigned char*>(disData), newlen, masterpwd, 32, ivi);
    ofstream writeSv(db+"Preferences/fn.iv",ios::binary|ios::out);
    if (!writeSv.good()) {
        cout<<"Fatal error! Failure in writing to fn.iv!"<<endl;
        cin.get();
        delete[] disData;
        delete[] fnameiv;
        return;
    }
    writeSv.write(reinterpret_cast<char *>(fnameiv),16);
    delete[] fnameiv;
    writeSv.close();
    writeSv.open(db+"Preferences/fn",ios::binary|ios::out);
    if (!writeSv.good()) {
        cout<<"Fatal error! Failure in writing to fn!"<<endl;
        cin.get();
        delete[] disData;
        return;
    }
    writeSv.write(disData,newlen);
    writeSv.close();
    delete[] disData;
}
string oldPwd;
int main() {
    clc();
    string usernm=(string)getlogin();
    bool trieddev=false;
    devJmp:
    if (!fs::exists("/Users/"+usernm)) {
        if (!trieddev) {
            cout<<"Autodir failed. Trying dev legitmichel777..."<<endl;
            usernm="legitmichel777";
            goto devJmp;
        } else {
            cout<<"Autodir failed. Please input your home directory."<<endl;
            getline(cin,usernm);
            goto devJmp;
        }
    }
    db="/Users/"+usernm+"/Library/Containers/com.mclm7.gringotts/";
    masterpwd=new unsigned char[32];
    if (!fs::exists(db+"Preferences/exists.flag")) {
        fs::create_directory("/Users/"+usernm+"/Library/Containers/com.mclm7.gringotts");
        fs::create_directory("/Users/"+usernm+"/Library/Containers/com.mclm7.gringotts/Preferences");
        fs::create_directory("/Users/"+usernm+"/Library/Containers/com.mclm7.gringotts/Encrypted");
        fs::create_directory("/Users/"+usernm+"/Library/Containers/com.mclm7.gringotts/Metadata");
        fs::create_directory("/Users/"+usernm+"/Library/Containers/com.mclm7.gringotts/Documents");
        fs::create_directory("/Users/"+usernm+"/Library/Containers/com.mclm7.gringotts/Temporary");
        ofstream install(db+"xxhsum",ios::binary);
        if (!install.good()) {
            cout<<"Error installing xxhsum!"<<endl;
        }
        const unsigned char* insdt;
        insdt=xxhsum();
        for (ll i=0;i<75932;i++) install<<insdt[i];
        install.close();
        fs::permissions(db+"xxhsum", fs::perms::group_exec|fs::perms::owner_exec|fs::perms::others_exec);
        //generate random key
        ofstream starter(db+"Preferences/exists.flag");
        starter.close();
        for (ll i=0;i<32;i++) masterpwd[i]=urandom_draw();
        cout<<"Welcome to Gringotts, a secure vault designed to keep all your files secure with the latest technologies."<<endl<<"Input the vault password. If you forget your password, your files will be lost."<<endl;
        string password;
        getline(cin,password);
        oldPwd=password;
        unsigned char *pwdslt=new unsigned char[16];
        for (ll i=0;i<16;i++) pwdslt[i]=urandom_draw();
        unsigned char *hashedpwd=new unsigned char[32];
        argon2id_hash_raw(50,16384,4,password.c_str(),password.size(), pwdslt, 16, hashedpwd, 32); //hash password
        unsigned char *encIv=new unsigned char[16];
        for (ll i=0;i<16;i++) encIv[i]=urandom_draw();
        vector<unsigned char*>ivi;
        ivi.push_back(encIv);
        unsigned char *encryptMasterpwd=new unsigned char[32];
        for (ll i=0;i<32;i++) encryptMasterpwd[i]=masterpwd[i];
        aes_encrypt(encryptMasterpwd,32,hashedpwd,32,ivi); //use hashed password to encrypt msater password
        //store password salt, encrypted master key, encryption iv
        ofstream credWrite(db+"Preferences/masterPassword",ios::binary|ios::out);
        if (!credWrite.good()) {
            cout<<"Fatal error! Failure in writing to masterPassword!"<<endl;
            cin.get();
            delete[] encryptMasterpwd;
            delete[] pwdslt;
            delete[] ivi[0];
            return 0;
        }
        credWrite.write(reinterpret_cast<char*>(encryptMasterpwd),32);
        credWrite.close();
        delete[] encryptMasterpwd;
        credWrite.open(db+"Preferences/masterPassword.salt",ios::binary|ios::out);
        if (!credWrite.good()) {
            cout<<"Fatal error! Failure in writing to masterPassword.salt!"<<endl;
            cin.get();
            delete[] pwdslt;
            delete[] ivi[0];
            return 0;
        }
        credWrite.write(reinterpret_cast<char*>(pwdslt),16);
        delete[] pwdslt;
        credWrite.close();
        credWrite.open(db+"Preferences/masterPassword.iv",ios::binary|ios::out);
        if (!credWrite.good()) {
            cout<<"Fatal error! Failure in writing to masterPassword.iv!"<<endl;
            cin.get();
            delete[] ivi[0];
            return 0;
        }
        credWrite.write(reinterpret_cast<char*>(ivi[0]),16);
        credWrite.close();
        delete[] ivi[0];
        doFsave();
    } else {
        cout<<"Welcome to the Gringotts secure vault. Your password?"<<endl;
        string password;
        getline(cin,password);
        oldPwd=password;
        unsigned char *pwdslt=new unsigned char[16];
        ifstream readCred(db+"Preferences/masterPassword.salt",ios::in|ios::binary);
        if (!readCred.good()) {
            cout<<"Fatal error! Failure in reading masterPassword.salt!"<<endl;
            cin.get();
            delete[] pwdslt;
            return 0;
        }
        readCred.read(reinterpret_cast<char *>(pwdslt),16);
        readCred.close();
        unsigned char *hashedpwd=new unsigned char[32];
        argon2id_hash_raw(50,16384,4,password.c_str(),password.size(), pwdslt, 16, hashedpwd, 32); //hash password
        unsigned char *encIv=new unsigned char[16];
        readCred.open(db+"Preferences/masterPassword.iv",ios::binary|ios::out);
        if (!readCred.good()) {
            delete[] hashedpwd;
            delete[] encIv;
            delete[] pwdslt;
            cout<<"Fatal error! Failure in reading masterPassword.iv!"<<endl;
            cin.get();
            return 0;
        }
        readCred.read(reinterpret_cast<char *>(encIv),16);
        readCred.close();
        vector<unsigned char*>ivi;
        ivi.push_back(encIv);
        readCred.open(db+"Preferences/masterPassword",ios::binary|ios::out);
        if (!readCred.good()) {
            cout<<"Fatal error! Failure in reading masterPassword!"<<endl;
            cin.get();
            delete[] hashedpwd;
            delete[] encIv;
            delete[] pwdslt;
            return 0;
        }
        readCred.read(reinterpret_cast<char *>(masterpwd),32);
        readCred.close();
        aes_decrypt(masterpwd,32,hashedpwd,32,ivi); //use hashed password to encrypt msater password
        delete[] hashedpwd;
        delete[] encIv;
        delete[] pwdslt;
        ifstream openfnames(db+"Preferences/fn.iv",ios::binary|ios::in);
        if (!openfnames.good()) {
            cout<<"Fatal error! Failure in reading fn.iv!"<<endl;
            cin.get();
            return 0;
        }
        unsigned char* fnIv=new unsigned char[16];
        ivi.clear();
        openfnames.read(reinterpret_cast<char *>(fnIv),16);
        ivi.push_back(fnIv);
        openfnames.close();
        openfnames.open(db+"Preferences/fn",ios::binary|ios::in);
        if (!openfnames.good()) {
            cout<<"Fatal error! Failure in reading fn!"<<endl;
            cin.get();
            delete[] fnIv;
            return 0;
        }
        string fcont((istreambuf_iterator<char>(openfnames)),istreambuf_iterator<char>());
        unsigned char* fconts=new unsigned char[fcont.size()];
        for (ll i=0;i<fcont.size();i++) fconts[i]=fcont[i];
        aes_decrypt(fconts,fcont.size(),masterpwd,32,ivi);
        stringstream readMp;
        for (ll i=0;i<fcont.size();i++) {
            readMp<<fconts[i];
        }
        delete[] fconts;
        delete[] fnIv;
        ll fcnt;
        readMp>>fcnt;
        readMp.get();
        for (ll i=0;i<fcnt;i++) {
            string fir,sec;
            getline(readMp,fir);
            getline(readMp,sec);
            if (i==fcnt-1) {
                sec=sec.substr(0,sec.find('\0'));
            }
            filnames[fir]=sec;
//            revfnames.insert(pair<string,string>(sec,fir));
        }
    }
    while (true) {
        clc();
        cout<<"Welcome to the Gringotts (v1.0). Please select an action."<<endl<<"[1]Enter Vault"<<endl<<"[2]Change Password"<<endl<<"[3]About"<<endl<<"[4]Quit"<<endl;
        string choiceInp;
        getline(cin,choiceInp);
        if (choiceInp=="1") {
            cout<<"Decrypting..."<<endl;
            set<string>checkNew;
            struct recurRebuild {
                string pth;
                string realPth;
            };
            stack<recurRebuild>dirExp;
            dirExp.push((recurRebuild){"",""}); //explore Encrypted/
            while (!dirExp.empty()) {
                string encprefx=db+"Encrypted";
                string toprefx=db+"Documents";
                string metprefx=db+"Metadata";
                recurRebuild cur=dirExp.top();
                dirExp.pop();
                for (const fs::directory_entry& entry : fs::directory_iterator(encprefx+cur.realPth)) {
                    string entryPrc=entry.path();
                    entryPrc=entryPrc.substr(encprefx.size());
                    string curNm=rdcPth(entryPrc); //pushes it down to barebones
                    if (curNm[0]=='.') continue;
                    if (filnames.find(curNm)==filnames.end()) continue;
                    curNm=filnames[curNm];
                    if (entry.is_directory()) {
                        curNm=cur.pth+"/"+curNm;
                        dirExp.push((recurRebuild){curNm,entryPrc});
                        fs::create_directory(toprefx+curNm);
                        checkNew.insert(curNm);
                    } else {
                        unsigned char* curFIv=new unsigned char[16];
                        ifstream rdMeta(metprefx+entryPrc+".encIv",ios::in|ios::binary);
                        if (!rdMeta.good()) {
                            delete[] curFIv;
                            continue;
                        }
                        rdMeta.read(reinterpret_cast<char *>(curFIv),16);
                        system(("openssl enc -d -aes-256-cbc -K "+uchar2hex(masterpwd, 32)+" -iv "+uchar2hex(curFIv, 16)+" -in "+safespace(encprefx+entryPrc)+" -out "+safespace(toprefx+cur.pth+"/"+curNm)).c_str());
                        checkNew.insert(cur.pth+"/"+curNm);
                        delete[] curFIv;
                    }
                }
            }
            cout<<"Decryption complete. You can now view and edit files inside of your vault. Press return to exit."<<endl;
            system(("open "+safespace(db+"Documents")).c_str());
            cin.get();
            dirExp.push((recurRebuild){"",""}); //explore Encrypted/
            //check for deleted items and overwrites
            map<string,string>correl;
            while (!dirExp.empty()) {
                string encprefx=db+"Encrypted";
                string toprefx=db+"Documents";
                string metprefx=db+"Metadata";
                recurRebuild cur=dirExp.top();
                correl[cur.pth]=cur.realPth;
                dirExp.pop();
                for (const fs::directory_entry& entry : fs::directory_iterator(encprefx+cur.realPth)) {
                    string entryPrc=entry.path();
                    entryPrc=entryPrc.substr(encprefx.size());
                    string curNm=rdcPth(entryPrc); //pushes it down to barebones
                    if (curNm[0]=='.') continue;
                    if (filnames.find(curNm)==filnames.end()) {
                        continue;
                    }
                    curNm=filnames[curNm];
                    if (entry.is_directory()) {
                        if (!fs::exists(toprefx+cur.pth+"/"+curNm)) {
                            if (filnames.find(rdcPth(entryPrc))==filnames.end()) continue;
                            else filnames.erase(filnames.find(rdcPth(entryPrc)));
                            stack<string>toRm;
                            toRm.push(entryPrc);
                            while (!toRm.empty()) {
                                string dis=toRm.top();
                                toRm.pop();
                                for (const fs::directory_entry& tormf : fs::directory_iterator(encprefx+dis)) {
                                    string letsRm=rdcPth(tormf.path());
                                    if (filnames.find(letsRm)==filnames.end()) continue;
                                    else filnames.erase(filnames.find(letsRm));
                                    if (tormf.is_directory()) {
                                        toRm.push(tormf.path().string().substr(encprefx.size()));
                                    }
                                }
                            }
                            fs::remove_all(encprefx+entryPrc);
                        } else {
                            curNm=cur.pth+"/"+curNm;
                            dirExp.push((recurRebuild){curNm,entryPrc});
                        }
                    } else {
                        unsigned char* curFIv=new unsigned char[16];
                        ifstream rdMeta(metprefx+entryPrc+".enciv",ios::in|ios::binary);
                        if (!rdMeta.good()) {
                            delete[] curFIv;
                            continue;
                        }
                        rdMeta.read(reinterpret_cast<char *>(curFIv),16);
                        if (!fs::exists(toprefx+cur.pth+"/"+curNm)) {
                            fs::remove(encprefx+entryPrc);
                            filnames.erase(filnames.find(rdcPth(entryPrc)));
                        } else {
                            //do hash check
                            system((safespace(db+"xxhsum")+" -q "+safespace(toprefx+cur.pth+"/"+curNm)+" > "+safespace(db+"Temporary/tmp.xxh64")).c_str());
                            //decrypt prior xxhf
                            //metprefx+entryPrc+".xxh64"
                            ifstream pxxh(metprefx+entryPrc+".hsh",ios::binary|ios::in);
                            if (!pxxh.good()) {
                                cout<<"Fatal error! Failure in reading hsh!"<<endl;
                                cin.get();
                                return 0;
                            }
                            string encpxxh((istreambuf_iterator<char>(pxxh)),istreambuf_iterator<char>());
                            pxxh.close();
                            unsigned char* pxxhd=new unsigned char[encpxxh.size()]; //cleared
                            for (ll i=0;i<encpxxh.size();i++) pxxhd[i]=encpxxh[i];
                            unsigned char* pxxhiv=new unsigned char[16]; //cleared
                            pxxh.open(metprefx+entryPrc+".hshIv",ios::binary|ios::in);
                            if (!pxxh.good()) {
                                cout<<"Fatal error! Failure in reading hshIv!"<<endl;
                                cin.get();
                                return 0;
                            }
                            pxxh.read(reinterpret_cast<char *>(pxxhiv), 16);
                            pxxh.close();
                            vector<unsigned char *>xxhivi;
                            xxhivi.push_back(pxxhiv);
                            aes_decrypt(pxxhd,encpxxh.size(),masterpwd,32,xxhivi);
                            delete[] pxxhiv;
                            ifstream readDis(db+"Temporary/tmp.xxh64",ios::in|ios::binary);
                            if (!readDis.good()) cout<<"Fatal error reading tmp.xxh64!"<<endl;
                            unsigned char* daHsh=new unsigned char[16]; //cleared
                            readDis.read(reinterpret_cast<char *>(daHsh),16);
                            readDis.close();
                            bool diff=false;
                            for (ll i=0;i<16&&!diff;i++) {
                                diff=(pxxhd[i]!=daHsh[i]);
                            }
                            delete[] daHsh;
                            if (diff) {
//                                cout<<"UPDT FILE"<<endl;
                                vector<unsigned char *>encIv;
                                unsigned char *hshiv=new unsigned char[16];
                                for (ll i=0;i<16;i++) hshiv[i]=urandom_draw();
                                encIv.push_back(hshiv);
                                aes_encrypt(pxxhd, 16, masterpwd, 32, encIv);
                                ofstream outputEnc(metprefx+entryPrc+".hshIv",ios::out|ios::binary);
                                outputEnc.write(reinterpret_cast<char *>(hshiv),16);
                                outputEnc.close();
                                outputEnc.open(metprefx+entryPrc+".hsh",ios::out|ios::binary);
                                outputEnc.write(reinterpret_cast<char *>(pxxhd),16);
                                outputEnc.close();
                                delete[] hshiv;
                                //encrypt it
                                unsigned char *curFIv=new unsigned char[16];
                                for (ll i=0;i<16;i++) curFIv[i]=urandom_draw();
                                system(("openssl enc -e -aes-256-cbc -K "+uchar2hex(masterpwd, 32)+" -iv "+uchar2hex(curFIv, 16)+" -in "+safespace(toprefx+cur.pth+"/"+curNm)+" -out "+safespace(encprefx+entryPrc)).c_str());
                                outputEnc.open(metprefx+entryPrc+".encIv",ios::out|ios::binary);
                                outputEnc.write(reinterpret_cast<char *>(curFIv),16);
                                outputEnc.close();
                                delete[] curFIv;
                            }
                            delete[] pxxhd;
                        }
                        delete[] curFIv;
                    }
                }
            }
            //check new content
            dirExp.push((recurRebuild){"",""}); //explore Documents/ for new content
            while (!dirExp.empty()) {
                string encprefx=db+"Encrypted";
                string docprefx=db+"Documents";
                string metprefx=db+"Metadata";
                recurRebuild cur=dirExp.top();
                dirExp.pop();
                //here, realpth is the uncoded ones and pth is coded
                for (const fs::directory_entry& entry : fs::directory_iterator(docprefx+cur.realPth)) {
                    string entryPrc=entry.path();
                    entryPrc=entryPrc.substr(docprefx.size());
                    string curNm=rdcPth(entryPrc); //pushes it down to barebones
                    if (curNm[0]=='.') continue;
                    if (entry.is_directory()) {
                        if (checkNew.find(entryPrc)==checkNew.end()) {
                            string newDirID;
                            while (true) {
                                newDirID=to_string(urandom_draw_ull());
                                if (filnames.find(newDirID)==filnames.end()) break;
                            }
                            dirExp.push((recurRebuild){cur.pth+"/"+newDirID,entryPrc});
                            fs::create_directory(encprefx+cur.pth+"/"+newDirID);
                            fs::create_directory(metprefx+cur.pth+"/"+newDirID);
                            //coded, uncoded
                            //add new name
                            filnames[newDirID]=curNm;
//                            revfilnames[curNm]=newDirID;
                        } else {
                            dirExp.push((recurRebuild){correl[entryPrc],entryPrc});
                        }
                    } else {
                        if (checkNew.find(entryPrc)==checkNew.end()) {
//                            cout<<"New file!"<<endl<<entryPrc<<endl;
                            string newfilID;
                            while (true) {
                                newfilID=to_string(urandom_draw_ull());
                                if (filnames.find(newfilID)==filnames.end()) break;
                            }
                            //add new name
                            filnames[newfilID]=curNm;
                            //hash it
                            system((safespace(db+"xxhsum")+" -q "+safespace(docprefx+cur.realPth+"/"+curNm)+" > "+safespace(db+"Temporary/hsh.xxh64")).c_str());
                            ifstream readDis(db+"Temporary/hsh.xxh64",ios::in|ios::binary);
                            if (!readDis.good()) cout<<"Fatal error reading hsh.xxh64!"<<endl;
                            unsigned char* daHsh=new unsigned char[16];
                            readDis.read(reinterpret_cast<char *>(daHsh),16);
                            readDis.close();
                            vector<unsigned char *>encIv;
                            unsigned char *hshiv=new unsigned char[16];
                            for (ll i=0;i<16;i++) hshiv[i]=urandom_draw();
                            encIv.push_back(hshiv);
                            aes_encrypt(daHsh, 16, masterpwd, 32, encIv);
                            ofstream outputEnc(metprefx+cur.pth+"/"+newfilID+".hshIv",ios::out|ios::binary);
                            outputEnc.write(reinterpret_cast<char *>(hshiv),16);
                            outputEnc.close();
                            outputEnc.open(metprefx+cur.pth+"/"+newfilID+".hsh",ios::out|ios::binary);
                            outputEnc.write(reinterpret_cast<char *>(daHsh),16);
                            outputEnc.close();
                            delete[] daHsh;
                            delete[] hshiv;
                            //encrypt it
                            unsigned char *curFIv=new unsigned char[16];
                            for (ll i=0;i<16;i++) curFIv[i]=urandom_draw();
                            system(("openssl enc -e -aes-256-cbc -K "+uchar2hex(masterpwd, 32)+" -iv "+uchar2hex(curFIv, 16)+" -in "+safespace(docprefx+cur.realPth+"/"+curNm)+" -out "+safespace(db+"Encrypted"+cur.pth+"/"+newfilID)).c_str());
                            outputEnc.open(metprefx+cur.pth+"/"+newfilID+".encIv",ios::out|ios::binary);
                            outputEnc.write(reinterpret_cast<char *>(curFIv),16);
                            delete[] curFIv;
                        }
                    }
                }
            }
            fs::remove_all(db+"Temporary/");
            fs::create_directory(db+"Temporary");
            fs::remove_all(db+"Documents/");
            fs::create_directory(db+"Documents");
            doFsave();
            cout<<"Files removed."<<endl;
        } else if (choiceInp=="2") {
            cout<<"Enter your current password."<<endl;
            string disold;
            getline(cin,disold);
            if (disold==oldPwd) {
                string newPw;
                cout<<"Enter your new password."<<endl;
                getline(cin,newPw);
                oldPwd=newPw;
                //rewrite masterpw
                unsigned char *pwdslt=new unsigned char[16];
                for (ll i=0;i<16;i++) pwdslt[i]=urandom_draw();
                unsigned char *hashedpwd=new unsigned char[32];
                argon2id_hash_raw(50,16384,4,newPw.c_str(),newPw .size(), pwdslt, 16, hashedpwd, 32); //hash password
                unsigned char *encIv=new unsigned char[16];
                for (ll i=0;i<16;i++) encIv[i]=urandom_draw();
                vector<unsigned char*>ivi;
                ivi.push_back(encIv);
                unsigned char *encryptMasterpwd=new unsigned char[32];
                for (ll i=0;i<32;i++) encryptMasterpwd[i]=masterpwd[i];
                aes_encrypt(encryptMasterpwd,32,hashedpwd,32,ivi); //use hashed password to encrypt msater password
                //store password salt, encrypted master key, encryption iv
                ofstream credWrite(db+"Preferences/masterPassword",ios::binary|ios::out);
                if (!credWrite.good()) {
                    cout<<"Fatal error! Failure in writing to masterPassword!"<<endl;
                    cin.get();
                    delete[] encryptMasterpwd;
                    delete[] pwdslt;
                    delete[] ivi[0];
                    return 0;
                }
                credWrite.write(reinterpret_cast<char*>(encryptMasterpwd),32);
                credWrite.close();
                delete[] encryptMasterpwd;
                credWrite.open(db+"Preferences/masterPassword.salt",ios::binary|ios::out);
                if (!credWrite.good()) {
                    cout<<"Fatal error! Failure in writing to masterPassword.salt!"<<endl;
                    cin.get();
                    delete[] pwdslt;
                    delete[] ivi[0];
                    return 0;
                }
                credWrite.write(reinterpret_cast<char*>(pwdslt),16);
                delete[] pwdslt;
                credWrite.close();
                credWrite.open(db+"Preferences/masterPassword.iv",ios::binary|ios::out);
                if (!credWrite.good()) {
                    cout<<"Fatal error! Failure in writing to masterPassword.iv!"<<endl;
                    cin.get();
                    delete[] ivi[0];
                    return 0;
                }
                credWrite.write(reinterpret_cast<char*>(ivi[0]),16);
                credWrite.close();
                delete[] ivi[0];
            } else {
                cout<<"Wrong password!"<<endl;
            }
        } else if (choiceInp=="3") {
            clc();
            cout<<"Gringotts system v1.0 designed by Michel."<<endl<<"Used libraries: Argon2, xxhash, and OpenSSL. Press return to return to main menu."<<endl;
            cin.get();
        } else if (choiceInp=="4") {
            return 0;
        } else cout<<"Error in input!"<<endl;
    }
    return 0;
}
//on system start, use PRNG to generate 32-bit key.
/*
 encrypt key with hashed password. Store hash salt in file. Store encrypted master key in file.
 Adding files: A finder drop box. placeholders for files with full directory structure. Use filesystem library
 viewing files: build directory structure. Next: Decrypt every file using openssl
 */
//name files and directories using random IDs
//metadata includes:
/*
 .encIv
 .hsh
 .hshIv
 */
