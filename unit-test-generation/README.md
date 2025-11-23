# Goal

The goal of this folder is to test prompting and running stragies with a few examples from CVE Fixes before moving to the LM Evaluation Harness


# Flow 

1. Build prompt with unit test harness
2. Send prompt to LLM
3. Parse LLM response
4. Execute unit test on vulnerable and non-vulnerable code
5. Collect results and generate report

## How to build a harness? 

The job of the harness is to setup the environment for the LLM to run the unit test

### Example Source Code that we would want to test

hns_rcb_get_ring_sset_count,82.0,['CVE-2017-18222'],['CWE-119'],"


Vulnerable example:

```c
int hns_rcb_get_ring_sset_count(int stringset)
{
	if (stringset == ETH_SS_STATS)
		return HNS_RING_STATIC_REG_NUM;

	return 0;
}

```


Fixed example:

```c
int hns_rcb_get_ring_sset_count(int stringset)
{
	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
		return HNS_RING_STATIC_REG_NUM;

	return 0;
}

```

```c

#ifndef HARNESS_H
#define HARNESS_H

#include <stdio.h>
#include <stdlib.h>

/* Call these to indicate test results */
#define RESULT_PASS()  do { printf("RESULT:PASS\n"); exit(0); } while (0)
#define RESULT_FAIL()  do { printf("RESULT:FAIL\n"); exit(1); } while (0)


// The LLM must implement this function to run the test
void run_test(void);



#endif /* HARNESS_H */


```