 

































































#include <jni.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <regex.h>
#include <math.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <android/log.h>

#define LOG_TAG "ZYGNK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define SLOT_CAP 256
#define MAX_RULES 256
#define MAX_DUMP 1048576           
#define MAX_RECURSE 8
#define RELOAD_CHECK_TICKS 1       

 
struct DynInfo {
    ElfW(Sym) *symtab; const char *strtab; uint32_t symcount;
    uintptr_t gnu_hash; uintptr_t sysv_hash;
    ElfW(Rela) *jmprel; size_t pltrelsz; ElfW(Rela) *rela; size_t relasz;
    uintptr_t span;
};
static int find_lib_base(const char *lib, uintptr_t *out) {
    static const size_t CAP = 2u << 20;
    char *buf = (char *)malloc(CAP); if (!buf) return -1;
    int fd = open("/proc/self/maps", O_RDONLY); if (fd < 0) { free(buf); return -1; }
    size_t t = 0;
    for (;;) { if (t >= CAP - 1) break; ssize_t n = read(fd, buf + t, CAP - 1 - t); if (n <= 0) break; t += n; }
    close(fd); buf[t] = 0;
    uintptr_t best = 0; char *save = NULL;
    for (char *l = strtok_r(buf, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        if (!strstr(l, lib)) continue;
        uintptr_t lo = strtoull(l, NULL, 16);
        if (best == 0 || lo < best) best = lo;
    }
    free(buf); if (!best) return -1; *out = best; return 0;
}
 
static uint32_t gnu_hash_count(uintptr_t a) {
    const uint32_t *h = (const uint32_t *)a;
    uint32_t nb = h[0], so = h[1], bs = h[2];
    if (!nb || !bs || bs > (1u << 20)) return 0;
    const uint64_t *bloom = (const uint64_t *)(h + 4);
    const uint32_t *bk = (const uint32_t *)((const char *)bloom + bs * 8);
    const uint32_t *chain = bk + nb;
    uint32_t mx = 0;
    for (uint32_t i = 0; i < nb; i++) if (bk[i] > mx) mx = bk[i];
    if (mx < so) return so;
    for (uint32_t g = 0; g < (4u << 20); g++) { if (chain[mx - so] & 1) return mx + 1; mx++; }
    return 0;
}
 
static uint32_t sysv_hash_count(uintptr_t a) {
    const uint32_t *h = (const uint32_t *)a;
    return h[1];  
}
static int parse_dyn(uintptr_t base, DynInfo *d) {
    memset(d, 0, sizeof(*d));
    ElfW(Ehdr) *e = (ElfW(Ehdr) *)base;
    if (memcmp(e->e_ident, ELFMAG, SELFMAG)) return -1;
    ElfW(Phdr) *ph = (ElfW(Phdr) *)(base + e->e_phoff);
    ElfW(Dyn) *dyn = 0;
    for (int i = 0; i < e->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) { uintptr_t en = base + ph[i].p_vaddr + ph[i].p_memsz; if (en > d->span) d->span = en; }
        if (ph[i].p_type == PT_DYNAMIC) dyn = (ElfW(Dyn) *)(base + ph[i].p_vaddr);
    }
    if (!dyn || !d->span) return -1;
    ElfW(Sym) *sy = 0; const char *st = 0;
    for (ElfW(Dyn) *p = dyn; p->d_tag != DT_NULL; p++) {
        switch (p->d_tag) {
            case DT_SYMTAB:  sy = (ElfW(Sym) *)(base + p->d_un.d_ptr); break;
            case DT_STRTAB:  st = (const char *)(base + p->d_un.d_ptr); break;
            case DT_GNU_HASH: d->gnu_hash = base + p->d_un.d_ptr; break;
            case DT_HASH:     d->sysv_hash = base + p->d_un.d_ptr; break;
            case DT_JMPREL:  d->jmprel = (ElfW(Rela) *)(base + p->d_un.d_ptr); break;
            case DT_PLTRELSZ: d->pltrelsz = p->d_un.d_val; break;
            case DT_RELA:    d->rela = (ElfW(Rela) *)(base + p->d_un.d_ptr); break;
            case DT_RELASZ:  d->relasz = p->d_un.d_val; break;
        }
    }
    if (!sy || !st) return -1;
    d->symtab = sy; d->strtab = st;
    if (d->gnu_hash) d->symcount = gnu_hash_count(d->gnu_hash);
    if (!d->symcount && d->sysv_hash) d->symcount = sysv_hash_count(d->sysv_hash);
    if ((uintptr_t)st > (uintptr_t)sy) {
        uint32_t cap = (uint32_t)(((uintptr_t)st - (uintptr_t)sy) / sizeof(ElfW(Sym)));
        if (!d->symcount || d->symcount > cap) d->symcount = cap;
    }
    if (!d->symcount || d->symcount > (1u << 21)) return -1;
    if ((uintptr_t)d->symtab < base || (uintptr_t)d->symtab > d->span) return -1;
    if ((uintptr_t)d->strtab < base || (uintptr_t)d->strtab > d->span) return -1;
    return 0;
}
 
static int slot_offset_ex(DynInfo *d, const char *exact, int fuzzy_kind, uintptr_t *off) {
    for (int pass = 0; pass < 2; pass++) {
        ElfW(Rela) *tab = pass ? d->rela : d->jmprel;
        size_t sz = pass ? d->relasz : d->pltrelsz;
        if (!tab || !sz) continue;
        size_t n = sz / sizeof(ElfW(Rela));
        for (size_t i = 0; i < n; i++) {
            uint32_t ty = ELF64_R_TYPE(tab[i].r_info);
            if (ty != R_AARCH64_JUMP_SLOT && ty != R_AARCH64_GLOB_DAT) continue;
            size_t si = ELF64_R_SYM(tab[i].r_info);
            if (si >= d->symcount) continue;
            const char *nm = d->strtab + d->symtab[si].st_name;
            int hit = 0;
            if (exact && strcmp(nm, exact) == 0) hit = 1;
            if (!hit && fuzzy_kind) {
                char low[128]; size_t L = strlen(nm); if (L >= sizeof low) continue;
                for (size_t k = 0; k < L; k++) low[k] = (char)tolower((unsigned char)nm[k]); low[L] = 0;
                if (strstr(low, "ssl") && strstr(low, fuzzy_kind > 0 ? "write" : "read")) hit = 1;
            }
            if (hit) { *off = tab[i].r_offset; return 1; }
        }
    }
    return 0;
}
static int slot_offset(DynInfo *d, const char *name, uintptr_t *off) { return slot_offset_ex(d, name, 0, off); }

struct Slot { void **addr; void *orig; };
static struct Slot g_slots[SLOT_CAP]; static int g_slot_n = 0;
 
static int page_orig_prot(void *a, int *out) {
    uintptr_t target=(uintptr_t)a;
    static const size_t CAP=2u<<20;
    char *buf=(char*)malloc(CAP); if(!buf)return -1;
    int fd=open("/proc/self/maps",O_RDONLY); if(fd<0){free(buf);return -1;}
    size_t t=0; for(;;){ if(t>=CAP-1)break; ssize_t n=read(fd,buf+t,CAP-1-t); if(n<=0)break; t+=n; }
    close(fd); buf[t]=0; int found=-1; char *save=NULL;
    for(char*l=strtok_r(buf,"\n",&save);l;l=strtok_r(NULL,"\n",&save)){
        unsigned long lo,hi; char pr[5]={0};
        if(sscanf(l,"%lx-%lx %4s",&lo,&hi,pr)!=3)continue;
        if(target>=lo&&target<hi){
            int p=PROT_NONE;
            if(pr[0]=='r')p|=PROT_READ;
            if(pr[1]=='w')p|=PROT_WRITE;
            if(pr[2]=='x')p|=PROT_EXEC;
            found=p; break;
        }
    }
    free(buf); if(found<0)return -1; *out=found; return 0;
}
static int unprotect(void *a, size_t n) {
    uintptr_t p = (uintptr_t)a & ~0xfffUL;
    size_t s = ((uintptr_t)a + n - p + 0xfff) & ~0xfffUL;
    return mprotect((void *)p, s, PROT_READ | PROT_WRITE);
}
static void patch_slot(void **slot, void *hook, const char *label) {
    if (g_slot_n >= SLOT_CAP) { LOGE("slot cap full, skip %s", label); return; }
    if (*slot == hook) { LOGI("slot already armed: %s", label); return; }   
    void *real = *slot;
    if (!real) { LOGE("slot unresolved: %s (lazy?)", label); return; }
    int origprot=0; int have=(page_orig_prot(slot,&origprot)==0);
    if (unprotect(slot, sizeof(void*))) return;
    g_slots[g_slot_n].addr = slot; g_slots[g_slot_n].orig = real; g_slot_n++;
    *slot = hook;
    if (have && !(origprot & PROT_WRITE)) {
        mprotect((void*)((uintptr_t)slot & ~0xfffUL), 0x1000, origprot);   
    }
    LOGI("patched %s slot=%p real=%p hook=%p", label, (void*)slot, real, hook);
}

 
static char g_pkg[160] = "app";
static char g_files_dir[200] = "/data/user/0/app/files/";
static void build_files_dir(void){
    int uid = getuid(); int user = 0;
    if (uid >= 10000) user = (uid - 10000) / 100000;
    snprintf(g_files_dir, sizeof g_files_dir, "/data/user/%d/%s/files/", user, g_pkg);
}
static const char* rules_path(void){ static char b[240]; snprintf(b,sizeof b,"%sflow_rules.txt",g_files_dir); return b; }

 
static jstring JNICALL stub_GCS(JNIEnv *env, jobject thiz) {
    (void)thiz; char buf[256];
    int n = snprintf(buf, sizeof buf, "[\"%s\",\"\",\"arm64-v8a\",\"\"]", g_pkg);
    if (n <= 0 || n >= (int)sizeof buf) return env->NewStringUTF("[]");
    return env->NewStringUTF(buf);
}
static jint JNICALL stub_GUS(JNIEnv *e, jobject t){(void)e;(void)t;return 0;}
static jboolean JNICALL stub_Pause(JNIEnv *e, jobject t){(void)e;(void)t;return JNI_TRUE;}
static jboolean JNICALL stub_Resume(JNIEnv *e, jobject t, jint v){(void)e;(void)t;(void)v;return JNI_TRUE;}
static jboolean JNICALL stub_SUI(JNIEnv *e, jobject t, jstring s){(void)e;(void)t;(void)s;return JNI_TRUE;}
static void JNICALL stub_STE(JNIEnv*e,jobject t,jint a,jint b,jfloat c,jfloat d,jfloat e2,jlong f,jint g,jobject h,jint i,jfloat j,jfloat k,jfloat l,jfloat m,jint n,jint o){
    (void)e;(void)t;(void)a;(void)b;(void)c;(void)d;(void)e2;(void)f;(void)g;(void)h;(void)i;(void)j;(void)k;(void)l;(void)m;(void)n;(void)o;
}
static jboolean JNICALL stub_Start(JNIEnv*e,jobject t,jobject a,jobject as,jstring v,jint fl,jstring c,jstring lang,jstring uuid){
    (void)e;(void)t;(void)a;(void)as;(void)v;(void)fl;(void)c;(void)lang;(void)uuid; return JNI_TRUE;
}
 


__attribute__((naked)) static void stub_generic(void){
    __asm__ volatile("mov x0, #1\n\tfmov s0, #1.0\n\tret\n");
}

 
typedef enum { ACT_LOG=0, ACT_PASS, ACT_HIDE, ACT_DROP } Action;
typedef enum { M_HOST=0, M_ASCII, M_HEX, M_LEN, M_WSOP, M_ENTROPY, M_REGEX, M_REGEXI, M_ANY, M_HOSTEQ, M_HOSTFULL } MatchType;
typedef struct {
    Action act; char dir; MatchType mt;
    char val[512];
    unsigned char hex[256]; int hexlen;
    int lo, hi;
    regex_t re; int re_ok;
    unsigned long hits;
} Rule;
typedef struct { Rule rules[MAX_RULES]; int n; int defW, defR; } RuleSet;
static RuleSet g_rs[2];
static volatile int g_rs_active = 0;
static struct stat g_rules_st; static int g_rules_st_ok = 0;

static int hexdec(const char *s, unsigned char *out, int cap) {
    int n = 0;
    while (*s && n < cap) {
        while (*s==' '||*s==',') s++;
        if (!*s) break;
        int hi = -1, lo = -1;
        if (*s>='0'&&*s<='9') hi=*s-'0'; else if (*s>='a'&&*s<='f') hi=*s-'a'+10; else if (*s>='A'&&*s<='F') hi=*s-'A'+10;
        s++; if (!*s) break;
        if (*s>='0'&&*s<='9') lo=*s-'0'; else if (*s>='a'&&*s<='f') lo=*s-'a'+10; else if (*s>='A'&&*s<='F') lo=*s-'A'+10;
        s++;
        if (hi<0||lo<0) break;
        out[n++]=(unsigned char)((hi<<4)|lo);
    }
    return n;
}
static void ascii_view(const unsigned char *b, int n, char *out) {
    int j=0; for(int i=0;i<n&&j<n;i++){unsigned char c=b[i];out[j++]=(c>=0x20&&c<0x7f)?(char)c:'.';} out[j]=0;
}
 
static void ensure_rules_file(void){
    struct stat st;
    if (stat(rules_path(), &st) == 0) return;
    FILE *f = fopen(rules_path(), "w"); if (!f) return;
    fputs("# ZygNuke auto-generated default rules (safe: LOG all, zero block)\n"
          "LOG B any\n"
          "# DROP = truly block outbound (W only), packet never leaves. BLOCK = alias of DROP.\n"
          "# HIDE = hide from log only (never touches packets, backward compat with old DROP).\n"
          "# Measured: anti-cheat endpoints hit 0 frames, so DROP is safe on precise rules.\n"
          "# DROP W regexi (DSDUC|api/token|RH012)\n", f);
    fclose(f);
    LOGI("rules template auto-created");
}
static int looks_pcre(const char *s){
     
    if (strstr(s,"(?:")||strstr(s,"(?i)")||strstr(s,"\\d")||strstr(s,"\\w")||strstr(s,"\\s")||strstr(s,"?+")||strstr(s,"*?")) return 1;
    return 0;
}
static void load_rules_into(RuleSet *rs) {
    memset(rs, 0, sizeof(*rs));
    FILE *f = fopen(rules_path(), "r"); if (!f) { LOGI("no rules file -> LOG all"); return; }
    char line[2048];
    while (fgets(line, sizeof line, f)) {
        char *p=line; while(*p==' '||*p=='\t')p++;
        if(!*p||*p=='#'||*p=='\n')continue;
        p[strcspn(p,"\r\n")]=0;
        char act[16],dir[8],mt[16]; char *val;
        if (sscanf(p,"%15s %7s %15s",act,dir,mt)<3) continue;
        val=p; int tok=0; char *q=p;
        while(*q){while(*q==' '||*q=='\t')q++;if(!*q)break;if(++tok==4){val=q;break;}while(*q&&*q!=' '&&*q!='\t')q++;}
        if(tok<4) val=(char*)"";
        if (!strcasecmp(act,"DEFAULT")) {
             
            if(!strcasecmp(dir,"W")){
                if(!strcasecmp(mt,"DROP")||!strcasecmp(mt,"BLOCK"))rs->defW=2;
                else if(!strcasecmp(mt,"HIDE"))rs->defW=1;
            }
            if(!strcasecmp(dir,"R")){
                if(!strcasecmp(mt,"DROP")||!strcasecmp(mt,"BLOCK"))rs->defR=2;
                else if(!strcasecmp(mt,"HIDE"))rs->defR=1;
            }
            continue;
        }
        if (rs->n>=MAX_RULES) { LOGE("rules truncated at %d (cap %d)", rs->n, MAX_RULES); break; }
        Rule *r=&rs->rules[rs->n]; memset(r,0,sizeof(*r));
         
        r->act=(!strcasecmp(act,"DROP")||!strcasecmp(act,"BLOCK"))?ACT_DROP
              :!strcasecmp(act,"HIDE")?ACT_HIDE
              :!strcasecmp(act,"PASS")?ACT_PASS:ACT_LOG;
        r->dir=toupper((unsigned char)dir[0]);
        if(!strcasecmp(mt,"host"))r->mt=M_HOST;
        else if(!strcasecmp(mt,"hosteq"))r->mt=M_HOSTEQ;
        else if(!strcasecmp(mt,"hostfull"))r->mt=M_HOSTFULL;
        else if(!strcasecmp(mt,"ascii"))r->mt=M_ASCII;
        else if(!strcasecmp(mt,"hex")){r->mt=M_HEX;r->hexlen=hexdec(val,r->hex,sizeof r->hex);}
        else if(!strcasecmp(mt,"len")){r->mt=M_LEN;sscanf(val,"%d-%d",&r->lo,&r->hi);}
        else if(!strcasecmp(mt,"wsop")){r->mt=M_WSOP;r->lo=(int)strtol(val,0,0);r->hi=r->lo;}
        else if(!strcasecmp(mt,"entropy")){r->mt=M_ENTROPY;r->lo=(int)(atof(val)*100);}
        else if(!strcasecmp(mt,"regex")||!strcasecmp(mt,"regexi")){
            r->mt=!strcasecmp(mt,"regexi")?M_REGEXI:M_REGEX;
            int fl=REG_EXTENDED|REG_NOSUB|(!strcasecmp(mt,"regexi")?REG_ICASE:0);
            int rc=regcomp(&r->re,val,fl); r->re_ok=(rc==0);
            if(rc){char eb[256];regerror(rc,&r->re,eb,sizeof eb);LOGE("regcomp fail [%s]: %s",val,eb);}
            else if(looks_pcre(val)) LOGE("POSIX ERE only; rule looks like PCRE: %s", val);
        } else r->mt=M_ANY;
        snprintf(r->val,sizeof r->val,"%s",val);
        r->hits=0; rs->n++;
    }
    fclose(f);
    LOGI("rules loaded n=%d defW=%d defR=%d", rs->n, rs->defW, rs->defR);
}
static void load_rules(void){
    int cur = __atomic_load_n(&g_rs_active, __ATOMIC_ACQUIRE);
    int nxt = cur ^ 1;
    load_rules_into(&g_rs[nxt]);
    __atomic_store_n(&g_rs_active, nxt, __ATOMIC_RELEASE);
    if (stat(rules_path(), &g_rules_st) == 0) g_rules_st_ok = 1;
}
 
static void reload_rules_if_changed(void){
    struct stat st;
    if (stat(rules_path(), &st) != 0) return;
    if (!g_rules_st_ok) { g_rules_st = st; g_rules_st_ok = 1; load_rules(); return; }
    if (st.st_mtime != g_rules_st.st_mtime || st.st_size != g_rules_st.st_size) {
        g_rules_st = st; LOGI("rules changed -> hot reload"); load_rules();
    }
}
 
static int entropy100(const unsigned char *b,int n){
    if(n<=0)return 0; int c[256]={0};for(int i=0;i<n;i++)c[b[i]]++;
    double H=0.0, inv=1.0/(double)n;
    for(int i=0;i<256;i++) if(c[i]){ double p=(double)c[i]*inv; H -= p*log2(p); }
    return (int)(H*100.0+0.5);
}
static int substr(const unsigned char *b,int n,const char *nd,int ci){
    int m=strlen(nd); if(m<=0||n<m)return 0;
    for(int k=0;k<=n-m;k++){int j=0;while(j<m){unsigned char x=b[k+j],y=(unsigned char)nd[j];if(ci){x=tolower(x);y=tolower(y);}if(x!=y)break;j++;}if(j==m)return 1;}
    return 0;
}
 
static int host_header_eq(const unsigned char *b,int n,const char *want){
    static const char key[]="host:"; int kl=(int)strlen(key);
    for(int k=0;k+kl<n;k++){
        int ok=1; for(int j=0;j<kl;j++){ if(tolower(b[k+j])!=key[j]){ok=0;break;} } if(!ok) continue;
        int s=k+kl; while(s<n&&(b[s]==' '||b[s]=='\t'))s++;
        int e=s; while(e<n&&b[e]!='\r'&&b[e]!='\n'&&b[e]!=' '&&b[e]!=':')e++;
        int m=(int)strlen(want);
        if(e-s!=m) continue;
        int eq=1; for(int j=0;j<m;j++){ if(tolower(b[s+j])!=tolower((unsigned char)want[j])){eq=0;break;} }
        if(eq) return 1;
    }
    return 0;
}
static Action apply(const void *buf,int len,char dir){
    const unsigned char *b=(const unsigned char*)buf;
    RuleSet *rs=&g_rs[__atomic_load_n(&g_rs_active,__ATOMIC_ACQUIRE)];
     
    Action def=(dir=='W')?((rs->defW==2)?ACT_DROP:(rs->defW==1)?ACT_HIDE:ACT_LOG)
                         :((rs->defR==2)?ACT_DROP:(rs->defR==1)?ACT_HIDE:ACT_LOG);
     


    int best_rank=0; Action ex_act=ACT_LOG; int has_explicit=0;
    char *view=NULL;
    for(int i=0;i<rs->n;i++){
        Rule *r=&rs->rules[i]; if(r->dir!='B'&&r->dir!=dir)continue;
        int hit=0;
        switch(r->mt){
            case M_ANY: hit=1; break;
            case M_HOST: hit=substr(b,len,r->val,1); break;
            case M_HOSTEQ: hit=host_header_eq(b,len,r->val); break;
            case M_HOSTFULL: hit=(len==(int)strlen(r->val)&&memcmp(b,r->val,len)==0); break;
            case M_ASCII: hit=substr(b,len,r->val,0); break;
            case M_HEX:
                if(r->hexlen>0&&len>=r->hexlen){for(int k=0;k<=len-r->hexlen;k++){int j=0;while(j<r->hexlen&&b[k+j]==r->hex[j])j++;if(j==r->hexlen){hit=1;break;}}}
                break;
            case M_LEN: hit=(len>=r->lo&&len<=r->hi); break;
            case M_WSOP: hit=(len>0&&(b[0]&0x0f)==(r->lo&0x0f)); break;
            case M_ENTROPY: hit=(entropy100(b,len)>=r->lo); break;
            case M_REGEX: case M_REGEXI:
                if(r->re_ok&&len>0){if(!view){view=(char*)malloc(len+1);ascii_view(b,len,view);}hit=(regexec(&r->re,view,0,0,0)==0);}
                break;
        }
        if(hit){r->hits++;
            int rank=(r->act==ACT_DROP)?3:(r->act==ACT_HIDE)?2:1;   
            if(rank>best_rank){best_rank=rank; ex_act=r->act; has_explicit=1;}
        }
    }
    if(view)free(view);
     
    if(!has_explicit) return def;
    if(ex_act==ACT_PASS) return ACT_LOG;
    return ex_act;
}

 
static __thread int t_depth=0;
static int fd_w=-1, fd_r=-1;
static pthread_mutex_t g_dump_mu = PTHREAD_MUTEX_INITIALIZER;
static void write_all(int fd,const char*q,int p){
    int off=0; while(off<p){ ssize_t w=write(fd,q+off,p-off); if(w<=0)break; off+=(int)w; }
}
static int netdump(int fd,char tag,const void*b,int n){
    if(fd<0||!b||n<=0) return 0;
    if(t_depth>=MAX_RECURSE) return 0;        
    t_depth++;
    Action a=apply(b,n,tag);
    int blocked=(a==ACT_DROP);    
    int hidden =(a==ACT_HIDE);    
    if(!hidden){
        int cap = n>MAX_DUMP?MAX_DUMP:n;
        static const char hx[]="0123456789abcdef";
        pthread_mutex_lock(&g_dump_mu);
        char head[32]; int hp=snprintf(head,sizeof head,"%c %d ",tag,n);
        write_all(fd,head,hp);
        char chunk[8192]; int cp=0;
        const unsigned char*bb=(const unsigned char*)b;
        for(int i=0;i<cap;i++){
            chunk[cp++]=hx[bb[i]>>4]; chunk[cp++]=hx[bb[i]&15];
            if(cp>=(int)sizeof chunk-2){ write_all(fd,chunk,cp); cp=0; }
        }
        if(cp>0) write_all(fd,chunk,cp);
        write_all(fd,"\n",1);
        pthread_mutex_unlock(&g_dump_mu);
    }
    t_depth--;
    return blocked;    
}
 



extern "C" __attribute__((visibility("default"),used)) int c_net_w(void*ssl,const void*buf,int len){(void)ssl;return netdump(fd_w,'W',buf,len);}
extern "C" __attribute__((visibility("default"),used)) void c_net_r(void*ssl,void*buf,int len){
    (void)ssl;
    int blocked=netdump(fd_r,'R',buf,len);
    if(blocked && buf && len>0){
        memset(buf,0,(size_t)len);    
        LOGI("R-direction DROP sanitized %d bytes",len);
    }
}

 
 

static void *g_fake_handle = 0;
static void init_fake_handle(void){
    if(g_fake_handle) return;
    g_fake_handle = dlopen("libdl.so", RTLD_NOW | RTLD_LOCAL);
    if(g_fake_handle) LOGI("fake handle ready %p", g_fake_handle);
    else LOGE("fake handle dlopen failed -> inert (real load)");
}
 

extern "C" __attribute__((visibility("default"),used)) int c_dlopen_check(const char* path){
    if(!g_fake_handle || !path) return 0;
     
    if(strstr(path,"librhcore") || strstr(path,"libRHCore") || strstr(path,"rhcore.so")){
        LOGI("rhcore load -> fake handle (no real map): %s", path);
        return 1;
    }
    return 0;
}
extern "C" __attribute__((visibility("default"),used)) void* c_get_fake_handle(void){ return g_fake_handle; }
 

__attribute__((naked)) static void dlstub(void){ __asm__ volatile(
  "sub sp,sp,#0xa0\n"
  "stp x0,x1,[sp,#0]\n""stp x2,x3,[sp,#0x10]\n""stp x4,x5,[sp,#0x20]\n""stp x6,x7,[sp,#0x30]\n"
  "stp x8,x9,[sp,#0x40]\n""stp x10,x11,[sp,#0x50]\n""stp x12,x13,[sp,#0x60]\n""stp x14,x15,[sp,#0x70]\n"
  "stp x16,x17,[sp,#0x80]\n""str x30,[sp,#0x90]\n"
  "bl c_dlopen_check\n"
  "cbz w0,1f\n"
  "bl c_get_fake_handle\n"    
  "ldr x30,[sp,#0x90]\n""add sp,sp,#0xa0\n""ret\n"
  "1:\n"
  "ldp x0,x1,[sp,#0]\n""ldp x2,x3,[sp,#0x10]\n""ldp x4,x5,[sp,#0x20]\n""ldp x6,x7,[sp,#0x30]\n"
  "ldp x8,x9,[sp,#0x40]\n""ldp x10,x11,[sp,#0x50]\n""ldp x12,x13,[sp,#0x60]\n""ldp x14,x15,[sp,#0x70]\n"
  "ldp x16,x17,[sp,#0x80]\n""ldr x30,[sp,#0x90]\n""add sp,sp,#0xa0\n"
  "ldr x16,#8\n""br x16\n"".quad 0x0\n"); }

 
 

extern "C" __attribute__((visibility("default"),used)) int c_open(const char* path){
    if(!path) return 0;
     
    const char *h=strstr(path,"rhtemp");
    if(h){
        LOGI("open rhtemp blocked: %s", path);
        return 1;
    }
    return 0;
}
 


__attribute__((naked)) static void ostub(void){ __asm__ volatile(
  "sub sp,sp,#0xa0\n"
  "stp x0,x1,[sp,#0]\n""stp x2,x3,[sp,#0x10]\n""stp x4,x5,[sp,#0x20]\n""stp x6,x7,[sp,#0x30]\n"
  "stp x8,x9,[sp,#0x40]\n""stp x10,x11,[sp,#0x50]\n""stp x12,x13,[sp,#0x60]\n""stp x14,x15,[sp,#0x70]\n"
  "stp x16,x17,[sp,#0x80]\n""str x30,[sp,#0x90]\n"
  "bl c_open\n"
  "cbz w0,1f\n"
  "mov w0,#-1\n"             
  "ldr x30,[sp,#0x90]\n""add sp,sp,#0xa0\n""ret\n"
  "1:\n"
  "ldp x0,x1,[sp,#0]\n""ldp x2,x3,[sp,#0x10]\n""ldp x4,x5,[sp,#0x20]\n""ldp x6,x7,[sp,#0x30]\n"
  "ldp x8,x9,[sp,#0x40]\n""ldp x10,x11,[sp,#0x50]\n""ldp x12,x13,[sp,#0x60]\n""ldp x14,x15,[sp,#0x70]\n"
  "ldp x16,x17,[sp,#0x80]\n""ldr x30,[sp,#0x90]\n""add sp,sp,#0xa0\n"
  "ldr x16,#8\n""br x16\n"".quad 0x0\n"); }

 
 
#define DEF_WSTUB(tag) \
__attribute__((naked)) static void wstub_##tag(void){ __asm__ volatile( \
  "sub sp,sp,#0xa0\n" \
  "stp x0,x1,[sp,#0]\n""stp x2,x3,[sp,#0x10]\n""stp x4,x5,[sp,#0x20]\n""stp x6,x7,[sp,#0x30]\n" \
  "stp x8,x9,[sp,#0x40]\n""stp x10,x11,[sp,#0x50]\n""stp x12,x13,[sp,#0x60]\n""stp x14,x15,[sp,#0x70]\n" \
  "stp x16,x17,[sp,#0x80]\n""str x30,[sp,#0x90]\n" \
  "bl c_net_w\n" \
  "cbz w0,1f\n" \
  "ldr w0,[sp,#0x10]\n"          \
  "ldr x30,[sp,#0x90]\n""add sp,sp,#0xa0\n""ret\n" \
  "1:\n" \
  "ldp x0,x1,[sp,#0]\n""ldp x2,x3,[sp,#0x10]\n""ldp x4,x5,[sp,#0x20]\n""ldp x6,x7,[sp,#0x30]\n" \
  "ldp x8,x9,[sp,#0x40]\n""ldp x10,x11,[sp,#0x50]\n""ldp x12,x13,[sp,#0x60]\n""ldp x14,x15,[sp,#0x70]\n" \
  "ldp x16,x17,[sp,#0x80]\n""ldr x30,[sp,#0x90]\n""add sp,sp,#0xa0\n" \
  "ldr x16,#8\n""br x16\n"".quad 0x0\n"); }
 
#define DEF_RSTUB(tag) \
__attribute__((naked)) static void rstub_##tag(void){ __asm__ volatile( \
  "sub sp,sp,#0x20\n""str x30,[sp,#0]\n""str x1,[sp,#8]\n" \
  "ldr x16,#44\n""blr x16\n""str x0,[sp,#0x10]\n" \
  "mov x2,x0\n""ldr x1,[sp,#8]\n""mov x0,xzr\n""bl c_net_r\n" \
  "ldr x0,[sp,#0x10]\n""ldr x30,[sp,#0]\n""add sp,sp,#0x20\n""ret\n"".quad 0x0\n"); }
DEF_WSTUB(ssr)
DEF_RSTUB(ssr)
DEF_WSTUB(jc)
DEF_RSTUB(jc)
DEF_WSTUB(ssl)
DEF_RSTUB(ssl)

static unsigned long *find_ldr_lit(void *fn, unsigned int next_op) {
    unsigned int *p=(unsigned int*)fn;
    for(int i=0;i<128;i++){
        unsigned int w=p[i];
        if((w&0xFFC0001Fu)!=0x58000010u)continue;
        if(next_op&&p[i+1]!=next_op)continue;
        long im=(w>>5)&0x7FFFFL; if(im&0x40000L)im-=0x80000L;
        return (unsigned long*)(p+i+im);
    }
    return 0;
}
static void *make_trampoline(void *real, long ps) {
    void *tr=mmap(0,ps,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(tr==MAP_FAILED)return 0;
    unsigned int *tp=(unsigned int*)tr; unsigned char *o=(unsigned char*)real;
    tp[0]=*(unsigned int*)(o);tp[1]=*(unsigned int*)(o+4);tp[2]=*(unsigned int*)(o+8);tp[3]=*(unsigned int*)(o+12);
    tp[4]=0x58000050u;tp[5]=0xd61f0200u;*(unsigned long*)(tp+6)=(unsigned long)(o+16);
    __builtin___clear_cache((char*)tr,(char*)tr+32);
    return tr;
}
static int write_lit(void *fn, unsigned int next_op, unsigned long val, long ps) {
    unsigned long *lit=find_ldr_lit(fn,next_op); if(!lit)return 0;
    void *pg=(void*)((unsigned long)lit&~(unsigned long)(ps-1));
    if(mprotect(pg,ps,PROT_READ|PROT_WRITE|PROT_EXEC)!=0)return 0;
    *lit=val; __builtin___clear_cache((char*)lit,(char*)lit+8);
    return (*lit==val);
}
 
static int install_write(uintptr_t base, DynInfo *d, const char **exact_list, void *wstub, long ps, const char *label) {
    uintptr_t off=0; int found=0; const char *used=0;
    for(int k=0;exact_list[k];k++){ if(slot_offset_ex(d,exact_list[k],1,&off)){used=exact_list[k];found=1;break;} }
    if(!found){LOGE("slot miss W %s",label);return 0;}
    void **slot=(void**)(base+off); void *real=*slot; if(!real){LOGE("slot unresolved W %s",label);return 0;}
    if(*slot==wstub){LOGI("W already armed %s",label);return 1;}
    void *tr=make_trampoline(real,ps); if(!tr){LOGE("trampoline fail W %s",label);return 0;}
    if(!write_lit(wstub,0xd61f0200u,(unsigned long)tr,ps)){LOGE("wstub lit fail %s",label);return 0;}
    patch_slot(slot,wstub,used);
    return (*slot==wstub)?1:0;
}
static int install_read(uintptr_t base, DynInfo *d, const char **exact_list, void *rstub, long ps, const char *label) {
    uintptr_t off=0; int found=0; const char *used=0;
    for(int k=0;exact_list[k];k++){ if(slot_offset_ex(d,exact_list[k],-1,&off)){used=exact_list[k];found=1;break;} }
    if(!found){LOGE("slot miss R %s",label);return 0;}
    void **slot=(void**)(base+off); void *real=*slot; if(!real){LOGE("slot unresolved R %s",label);return 0;}
    if(*slot==rstub){LOGI("R already armed %s",label);return 1;}
    if(!write_lit(rstub,0xd63f0200u,(unsigned long)real,ps)){LOGE("rstub lit fail %s",label);return 0;}
    patch_slot(slot,rstub,used);
    return (*slot==rstub)?1:0;
}
 
static int install_open(uintptr_t base, DynInfo *d, long ps){
    uintptr_t off=0;
    if(!slot_offset(d,"open",&off)||!off){LOGE("open slot miss");return 0;}
    void **slot=(void**)(base+off); void *real=*slot;
    if(!real){LOGE("open slot unresolved");return 0;}
    if(*slot==(void*)ostub){LOGI("open already armed");return 1;}
    void *tr=make_trampoline(real,ps); if(!tr){LOGE("open trampoline fail");return 0;}
    if(!write_lit((void*)ostub,0xd61f0200u,(unsigned long)tr,ps)){LOGE("ostub lit fail");return 0;}
    patch_slot(slot,(void*)ostub,"open@libjavacore");
    return (*slot==(void*)ostub)?1:0;
}
 

static int g_dlopen_armed=0;
static int install_dlopen_fake(long ps){
    if(!g_fake_handle) return 0;
    uintptr_t b=0;
    if(find_lib_base("libnativeloader.so",&b)!=0 || !b){LOGE("libnativeloader not found");return 0;}
    DynInfo d; if(parse_dyn(b,&d)!=0){LOGE("libnativeloader parse fail");return 0;}
    uintptr_t off=0;
    if(!slot_offset(&d,"android_dlopen_ext",&off)||!off){LOGE("android_dlopen_ext slot miss");return 0;}
    void **slot=(void**)(b+off); void *real=*slot;
    if(!real){LOGE("android_dlopen_ext unresolved");return 0;}   
    if(*slot==(void*)dlstub){g_dlopen_armed=1;return 1;}
    void *tr=make_trampoline(real,ps); if(!tr){LOGE("dlopen trampoline fail");return 0;}
    if(!write_lit((void*)dlstub,0xd61f0200u,(unsigned long)tr,ps)){LOGE("dlstub lit fail");return 0;}
    patch_slot(slot,(void*)dlstub,"android_dlopen_ext@nativeloader");
    g_dlopen_armed=(*slot==(void*)dlstub)?1:0;
    return g_dlopen_armed;
}

 
typedef void *(*fn_dlsym)(void *, const char *);
static fn_dlsym g_orig_dlsym = 0;
static const char *jni_method_tail(const char *sym, const char *cls_token) {
    const char *hit = strstr(sym, cls_token);
    if (!hit) return 0;
    const char *us = strchr(hit + strlen(cls_token), '_');
    if (!us) return 0;
    return us + 1;
}
static void *hook_dlsym(void *handle, const char *sym) {
    if (sym && strncmp(sym, "Java_", 5) == 0) {
        const char *m = jni_method_tail(sym, "RHNativeWrapper");
        if (m) {
            if (strcmp(m, "GCS")==0 || strncmp(m,"GCS_",4)==0)   return (void*)stub_GCS;
            if (strcmp(m, "GUS")==0 || strncmp(m,"GUS_",4)==0)   return (void*)stub_GUS;
            if (strcmp(m, "Pause")==0 || strncmp(m,"Pause_",6)==0) return (void*)stub_Pause;
            if (strcmp(m, "Resume")==0|| strncmp(m,"Resume_",7)==0)return (void*)stub_Resume;
            if (strcmp(m, "SUI")==0 || strncmp(m,"SUI_",4)==0)   return (void*)stub_SUI;
            if (strcmp(m, "STE")==0 || strncmp(m,"STE_",4)==0)   return (void*)stub_STE;
            if (strcmp(m, "Start")==0|| strncmp(m,"Start_",6)==0) return (void*)stub_Start;
            LOGE("unknown RHNativeWrapper method %s -> generic stub", m);
            return (void*)stub_generic;    
        }
    }
    return g_orig_dlsym(handle, sym);
}
 

static void sever_dlsym_in(const char *lib, const char *label) {
    uintptr_t base=0;
    if (find_lib_base(lib, &base)!=0 || !base) return;
    DynInfo d; if (parse_dyn(base, &d)!=0) return;
    uintptr_t off=0;
    if (!slot_offset(&d, "dlsym", &off) || !off) return;
    void **slot=(void**)(base+off); void *real=*slot;
    if (!real) return;                        
    if (!g_orig_dlsym) g_orig_dlsym=(fn_dlsym)real;    
    if (*slot==(void*)hook_dlsym) return;     
    patch_slot(slot,(void*)hook_dlsym,label);
}
static void sever_dlsym_sync(void) {
     
    sever_dlsym_in("libart.so","dlsym@libart");
    if (!g_orig_dlsym) { LOGE("dlsym not captured (lazy); retry in worker"); return; }
     
    sever_dlsym_in("librhcore.so","dlsym@rhcore");
    sever_dlsym_in("libc++_shared.so","dlsym@cxxshared");
    sever_dlsym_in("libssr.so","dlsym@ssr");
    LOGI("dlsym severed real=%p", (void*)g_orig_dlsym);
}

 
struct NetState { int ssr_w, ssr_r, jc_w, jc_r, ssl_w, ssl_r, javacore_open; };
static struct NetState g_net;
static const char *W_SSR[]={"ssl_write_internal","SSL_write",0};
static const char *R_SSR[]={"ssl_read_internal","SSL_read",0};
static const char *W_JC[] ={"SSL_write",0};
static const char *R_JC[] ={"SSL_read",0};
static const char *W_SSL[]={"SSL_write",0};
static const char *R_SSL[]={"SSL_read",0};
static void arm_net_once(long ps){
    if(!g_net.ssr_w||!g_net.ssr_r){ uintptr_t b=0;
        if(find_lib_base("libssr.so",&b)==0){ DynInfo d; if(parse_dyn(b,&d)==0){
            if(!g_net.ssr_w){g_net.ssr_w=install_write(b,&d,W_SSR,(void*)wstub_ssr,ps,"ssr-W")?1:0;}
            if(!g_net.ssr_r){g_net.ssr_r=install_read (b,&d,R_SSR,(void*)rstub_ssr,ps,"ssr-R")?1:0;}
        }}
    }
    if(!g_net.jc_w||!g_net.jc_r){ uintptr_t b=0;
        if(find_lib_base("libjavacrypto.so",&b)==0){ DynInfo d; if(parse_dyn(b,&d)==0){
            if(!g_net.jc_w){g_net.jc_w=install_write(b,&d,W_JC,(void*)wstub_jc,ps,"jc-W")?1:0;}
            if(!g_net.jc_r){g_net.jc_r=install_read (b,&d,R_JC,(void*)rstub_jc,ps,"jc-R")?1:0;}
        }}
    }
     
    if(!g_net.ssl_w||!g_net.ssl_r){ uintptr_t b=0;
        if(find_lib_base("libssl.so",&b)==0){ DynInfo d; if(parse_dyn(b,&d)==0){
            if(!g_net.ssl_w){g_net.ssl_w=install_write(b,&d,W_SSL,(void*)wstub_ssl,ps,"ssl-W")?1:0;}
            if(!g_net.ssl_r){g_net.ssl_r=install_read (b,&d,R_SSL,(void*)rstub_ssl,ps,"ssl-R")?1:0;}
        }}
    }
     
    if(!g_net.javacore_open){ uintptr_t b=0;
        if(find_lib_base("libjavacore.so",&b)==0){ DynInfo d; if(parse_dyn(b,&d)==0){
            g_net.javacore_open=install_open(b,&d,ps)?1:0;
        }}
    }
}

 
static int vm_module_in_maps(void){
    uintptr_t s=0; return (find_lib_base("rhtemp/save",&s)==0 && s);
}
static int vm_module_in_phdr(void){
    int seen=0;
    dl_iterate_phdr([](struct dl_phdr_info*info,size_t,void*data)->int{
        if(info->dlpi_name && strstr(info->dlpi_name,"rhtemp/save")) *(int*)data=1;
        return 0;
    }, &seen);
    return seen;
}
static void alarm_log(const char*msg){
    pthread_mutex_lock(&g_dump_mu);
    char p[256]; int n=snprintf(p,sizeof p,"# WATCHDOG %s\n",msg);
    if(fd_w>=0) write_all(fd_w,p,n);
    pthread_mutex_unlock(&g_dump_mu);
}

static volatile int g_stop=0;
static void *worker(void*) {
     
    long ps=sysconf(_SC_PAGESIZE);
    char p[256];
    snprintf(p,sizeof p,"%sflow_w.txt",g_files_dir); fd_w=open(p,O_WRONLY|O_CREAT|O_APPEND,0666);
    snprintf(p,sizeof p,"%sflow_r.txt",g_files_dir); fd_r=open(p,O_WRONLY|O_CREAT|O_APPEND,0666);
    ensure_rules_file();           
    load_rules();
    arm_net_once(ps);              
    LOGI("network armed w=%d/%d/%d r=%d/%d/%d javacore_open=%d",g_net.ssr_w,g_net.jc_w,g_net.ssl_w,g_net.ssr_r,g_net.jc_r,g_net.ssl_r,g_net.javacore_open);
    int ticks=0, alarmed=0;
    while(!g_stop){
        sleep(15); ticks++;
        if(!g_dlopen_armed) install_dlopen_fake(ps);    
        sever_dlsym_sync();                           
        arm_net_once(ps);                             
        if(ticks % RELOAD_CHECK_TICKS == 0) reload_rules_if_changed();   
        if(ticks % 4 == 0){
            int in_maps=vm_module_in_maps(), in_phdr=vm_module_in_phdr();
            if(in_maps||in_phdr){
                if(!alarmed){
                    LOGE("WATCHDOG ALARM: VM module appeared (maps=%d phdr=%d)",in_maps,in_phdr);
                    alarm_log("VM module appeared - re-sever");
                    sever_dlsym_sync();               
                    alarmed=1;
                }
            } else if(alarmed && !in_maps && !in_phdr){
                alarm_log("VM module gone"); alarmed=0;
            }
        }
    }
    return 0;
}

 
struct ModuleAbi { long api_version; void *impl; void(*preApp)(void*,void*); void(*postApp)(void*,const void*); void(*preServer)(void*,void*); void(*postServer)(void*,const void*); };
static void pre_app(void*,void*){}
static void pre_server(void*,void*){}
static void post_server(void*,const void*){}
static void post_app(void*,const void*){
    char pkg[160]; int fd=open("/proc/self/cmdline",O_RDONLY); if(fd<0)return;
    ssize_t n=read(fd,pkg,sizeof(pkg)-1); close(fd); if(n<=0)return; pkg[n]=0;
    if(!(strstr(pkg,"chaoszero") && strstr(pkg,"smilegate"))) return;
    snprintf(g_pkg, sizeof g_pkg, "%s", pkg);
    build_files_dir();
    LOGI("target matched %s (v6 fake-handle candidate)",pkg);
    sever_dlsym_sync();               
     
    long ps0=sysconf(_SC_PAGESIZE);
    init_fake_handle();
    install_dlopen_fake(ps0);
    pthread_t tid; if(pthread_create(&tid,0,worker,0)==0)pthread_detach(tid);
}
extern "C" __attribute__((visibility("default")))
void zygisk_module_entry(void **table, JNIEnv *env){
    (void)env; static ModuleAbi abi;
    abi.api_version=4; abi.impl=(void*)&g_stop;
    abi.preApp=pre_app; abi.postApp=post_app; abi.preServer=pre_server; abi.postServer=post_server;
    auto reg=reinterpret_cast<bool(*)(void**,ModuleAbi*)>(table[1]); reg(table,&abi);
}
