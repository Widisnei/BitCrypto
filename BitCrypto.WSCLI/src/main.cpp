#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

static inline int b64idx(char c){ if('A'<=c&&c<='Z') return c-'A'; if('a'<=c&&c<='z') return c-'a'+26; if('0'<=c&&c<='9') return c-'0'+52; if(c=='+') return 62; if(c=='/') return 63; if(c=='=') return -1; return -2; }
static std::vector<uint8_t> base64_decode(const std::string& s){ std::vector<uint8_t> out; int val=0, valb=-8; for (unsigned char c: s){ int d=b64idx(c); if(d==-2) continue; if(d==-1){ break; } val=(val<<6)+d; valb+=6; if(valb>=0){ out.push_back((uint8_t)((val>>valb)&0xFF)); valb-=8;} } return out; }
static bool read_compact_size(const std::vector<uint8_t>& in, size_t& off, uint64_t& v){ if(off>=in.size()) return false; uint8_t ch=in[off++]; if(ch<0xFD){ v=ch; return true; } if(ch==0xFD){ if(off+2>in.size()) return false; v=(uint64_t)in[off]|((uint64_t)in[off+1]<<8); off+=2; return true; } if(ch==0xFE){ if(off+4>in.size()) return false; v=0; for(int i=0;i<4;i++) v|=(uint64_t)in[off+i]<<(8*i); off+=4; return true; } if(ch==0xFF){ if(off+8>in.size()) return false; v=0; for(int i=0;i<8;i++) v|=(uint64_t)in[off+i]<<(8*i); off+=8; return true; } return false; }
int main(int argc,char**argv){
    std::string b64; for(int i=1;i<argc;i++){ std::string a=argv[i]; if(a=="--psbt"&&i+1<argc) b64=argv[++i]; if(a=="-h"||a=="--help"){ std::cout<<"BitCrypto.WSCLI --psbt <PSBTv2_BASE64>\n"; return 0; } }
    if(b64.empty()){ std::cerr<<"use --psbt <PSBTv2_BASE64>\n"; return 1; }
    auto raw = base64_decode(b64);
    size_t off=0; bool any=false; int idx=0;
    while(off<raw.size()){
        uint64_t klen=0; if(!read_compact_size(raw,off,klen)) break; if(klen==0) continue; if(off+klen>raw.size()) break; const uint8_t* k=&raw[off]; off+=klen;
        uint64_t vlen=0; if(!read_compact_size(raw,off,vlen)) break; if(off+vlen>raw.size()) break; const uint8_t* v=&raw[off]; off+=vlen;
        if(klen==1 && k[0]==0x0a){
            any=true; std::vector<uint8_t> w(v,v+vlen);
            size_t o=0; uint64_t items=0; if(!read_compact_size(w,o,items)) { idx++; continue; }
            std::cout<<"in["<<idx<<"] witness_items="<<items;
            std::vector<uint64_t> sizes; std::vector<std::string> preview;
            auto hex2 = [](const uint8_t* p, size_t n){ static const char* he="0123456789abcdef"; std::string s; s.reserve(n*2); for(size_t i=0;i<n;i++){ s.push_back(he[(p[i]>>4)&15]); s.push_back(he[p[i]&15]); } return s; };
            for(uint64_t t=0;t<items;t++){
                uint64_t L=0; if(!read_compact_size(w,o,L)) { break; }
                if (o+L>w.size()) { break; }
                sizes.push_back(L);
                const uint8_t* dp = w.data()+o;
                if (L<=32){ preview.push_back(hex2(dp, (size_t)L)); }
                else { std::string a = hex2(dp, 8); std::string b = hex2(dp+L-8, 8); preview.push_back(a+".."+b); }
                o += (size_t)L;
                if (t==items-1 && L>=33 && ((L-33)%32)==0){
                    int depth=(int)((L-33)/32);
                    std::cout<<" tap_control_block_depth="<<depth;
                }
            }
            std::cout<<" witness_sizes=[";
            for(size_t qi=0; qi<sizes.size(); ++qi){ if(qi) std::cout<<","; std::cout<<sizes[qi]; }
            std::cout<<"]";
            std::cout<<" witness_preview=[";
            for(size_t qi=0; qi<preview.size(); ++qi){ if(qi) std::cout<<","; std::cout<<"'"<<preview[qi]<<"'"; }
            std::cout<<"]\\n"; idx++;
        }
    }
    if(!any) std::cout<<"witness_items=0\n";
    return 0;
}
