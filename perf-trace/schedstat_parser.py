def cpumask_to_cpulist(cpumask):
    n = int(cpumask, 16)
    cpulist = []
    iterator = 0

    while n!=0:
        if n%2 == 1:
            cpulist.append(iterator)
        n //= 2
        iterator += 1

    return cpulist

class CpuTopology:
    def __init__(self):
        self.topology = dict()
        self.get_cpu_topology()
        self.llc_sd_id = self.get_llc_sd()

    def get_cpu_topology(self):
        cpuid = -1
        domain_id = -1
        for line in open("/proc/schedstat"):
            if line.startswith("domain"):
                domain_id = int(line.split()[0][6:])
                cpumask = line.split()[1]
                cpumask = "0x"+cpumask
                cpumask = cpumask.replace(",", "")
                self.topology[cpuid][domain_id] = cpumask_to_cpulist(cpumask)
               # print(cpumask, "sdsd", cpumask_to_cpulist(cpumask))
            if line.startswith("cpu"):
                cpuid = int(line.split()[0][3:])
                self.topology[cpuid] = dict()

    def get_llc_sd(self):
        import os
        domain_list = sorted(os.listdir("/proc/sys/kernel/sched_domain/cpu0/"), reverse=True)
    
        for domain_id in domain_list:
            for line in open("/proc/sys/kernel/sched_domain/cpu0/%s/flags"%(domain_id)):
                if "SD_SHARE_PKG_RESOURCES" in line:
                    return int(domain_id[6:])

    def llc_sibling(self, cpu):
        return self.topology[cpu][self.llc_sd_id]
