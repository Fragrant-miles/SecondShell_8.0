#include <jni.h>
#include <string>
#include <unistd.h>
#include <android/log.h>
#include <fcntl.h>
#include <asm/fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>
//import c header
extern "C" {
#include "hook/dlfcn/dlfcn_compat.h"
#include "hook/include/inlineHook.h"
}
typedef unsigned char byte;
#define TAG "SecondShell"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
struct DexFile {
    // Field order required by test "ValidateFieldOrderOfJavaCppUnionClasses".
    // The class we are a part of.
    uint32_t declaring_class_;
    // Access flags; low 16 bits are defined by spec.
    void *begin;
    /* Dex file fields. The defining dex file is available via declaring_class_->dex_cache_ */
    // Offset to the CodeItem.
    uint32_t size;
};
struct ArtMethod {
    // Field order required by test "ValidateFieldOrderOfJavaCppUnionClasses".
    // The class we are a part of.
    uint32_t declaring_class_;
    // Access flags; low 16 bits are defined by spec.
    uint32_t access_flags_;
    /* Dex file fields. The defining dex file is available via declaring_class_->dex_cache_ */
    // Offset to the CodeItem.
    uint32_t dex_code_item_offset_;
    // Index into method_ids of the dex file associated with this method.
    uint32_t dex_method_index_;
};

void* *(*oriexecve)(const char *__file, char *const *__argv, char *const *__envp);

void* *myexecve(const char *__file, char *const *__argv, char *const *__envp) {
    LOGD("process:%d,enter execve:%s", getpid(), __file);
    if (strstr(__file, "dex2oat")) {
        return NULL;
    } else {
        return oriexecve(__file, __argv, __envp);
    }


}

//void ClassLinker::LoadMethod(Thread* self, const DexFile& dex_file, const ClassDataItemIterator& it,Handle<mirror::Class> klass, ArtMethod* dst)
void *(*oriloadmethod)(void *, void *, void *, void *, void *);

void *myloadmethod(void *a, void *b, void *c, void *d, void *e) {
    LOGD("process:%d,before run loadmethod:", getpid());
    struct ArtMethod *artmethod = (struct ArtMethod *) e;
    struct DexFile *dexfile = (struct DexFile *) b;
    LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d", getpid(), dexfile->begin,
         dexfile->size);//0,57344
    char dexfilepath[100] = {0};
    sprintf(dexfilepath, "/sdcard/%d_%d.dex", dexfile->size, getpid());
    int fd = open(dexfilepath, O_CREAT | O_RDWR, 0666);
    if (fd > 0) {
        write(fd, dexfile->begin, dexfile->size);
        close(fd);
    }

    void *result = oriloadmethod(a, b, c, d, e);
    LOGD("process:%d,enter loadmethod:code_offset:%d,idx:%d", getpid(),
         artmethod->dex_code_item_offset_, artmethod->dex_method_index_);

    byte *code_item_addr = static_cast<byte *>(dexfile->begin) + artmethod->dex_code_item_offset_;
    LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,beforedumpcodeitem:%p", getpid(),
         dexfile->begin, dexfile->size, code_item_addr);


    if (artmethod->dex_method_index_ == 15203) {//TestClass.testFunc->methodidx
        LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,start repire method", getpid(),
             dexfile->begin, dexfile->size);
        byte *code_item_addr = (byte *) dexfile->begin + artmethod->dex_code_item_offset_;
        LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,beforedumpcodeitem:%p", getpid(),
             dexfile->begin, dexfile->size, code_item_addr);

        int result = mprotect(dexfile->begin, dexfile->size, PROT_WRITE);
        byte *code_item_start = static_cast<byte *>(code_item_addr) + 16;
        LOGD("process:%d,enter loadmethod:dexfilebegin:%p,size:%d,code_item_start:%p", getpid(),
             dexfile->begin, dexfile->size, code_item_start);
        byte inst[16] = {0x1a, 0x00, 0xed, 0x34, 0x1a, 0x01, 0x43, 0x32, 0x71, 0x20, 0x91, 0x05,
                         0x10, 0x00, 0x0e, 0x00};
        for (int i = 0; i < sizeof(inst); i++) {
            code_item_start[i] = inst[i];
        }
        //2343->i am from com.kanxue.test02.TestClass.testFunc
        code_item_start[2] = 0x43;//34ed->kanxue
        code_item_start[3] = 0x23;
        memset(dexfilepath, 0, 100);
        sprintf(dexfilepath, "/sdcard/%d_%d.dex_15203_2", dexfile->size, getpid());
        fd = open(dexfilepath, O_CREAT | O_RDWR, 0666);
        if (fd > 0) {
            write(fd, dexfile->begin, dexfile->size);
            close(fd);
        }
    }
    LOGD("process:%d,after loadmethod:code_offset:%d,idx:%d", getpid(),
         artmethod->dex_code_item_offset_, artmethod->dex_method_index_);//0,57344
    return result;

}

void hooklibc() {
    LOGD("go into hooklibc");
    //7.0 命名空间限制
    void *libc_addr = dlopen_compat("libc.so", RTLD_NOW);
    void *execve_addr = dlsym_compat(libc_addr, "execve");
    if (execve_addr != NULL) {
        if (ELE7EN_OK == registerInlineHook((uint32_t) execve_addr, (uint32_t) myexecve,
                                            (uint32_t **) &oriexecve)) {
            if (ELE7EN_OK == inlineHook((uint32_t) execve_addr)) {
                LOGD("inlineHook execve success");
            } else {
                LOGD("inlineHook execve failure");
            }
        }
    }
}

void hookART() {
    LOGD("go into hookART");
    void *libart_addr = dlopen_compat("/system/lib/libart.so", RTLD_NOW);
    if (libart_addr != NULL) {
        void *loadmethod_addr = dlsym_compat(libart_addr,
                                             "_ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE");
        if (loadmethod_addr != NULL) {
            if (ELE7EN_OK == registerInlineHook((uint32_t) loadmethod_addr, (uint32_t) myloadmethod,
                                                (uint32_t **) &oriloadmethod)) {
                if (ELE7EN_OK == inlineHook((uint32_t) loadmethod_addr)) {
                    LOGD("inlineHook loadmethod success");
                } else {
                    LOGD("inlineHook loadmethod failure");
                }
            }
        }
    }


}

extern "C" JNIEXPORT jstring JNICALL
Java_com_kanxue_secondshell_180_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "ART SecondShell";
    return env->NewStringUTF(hello.c_str());
}
extern "C" JNIEXPORT void JNICALL
Java_com_kanxue_secondshell_180_MainActivity_SecondShell(
        JNIEnv *env,
        jobject /* this */) {
    hooklibc();
    hookART();
    return;
}