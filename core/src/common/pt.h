/*
 * Protothreads: cooperative multithreading for C (single header).
 *
 * Combined from:
 *   - pt.h       (protothreads core)
 *   - pt-sem.h   (counting semaphores)
 *   - lc-addrlabels.h (local continuations, GCC "labels as values")
 *
 * Original copyright (c) 2004-2006, Swedish Institute of Computer Science.
 * All rights reserved. See Contiki and protothreads licensing terms.
 * Author: Adam Dunkels <adam@sics.se>
 *
 * This implementation uses GCC's "labels as values" extension for
 * local continuations. No separate lc.h / lc-addrlabels.h is required;
 * continuation state is stored in struct pt and used only by PT_* macros.
 */

#ifndef __PT_H__
#define __PT_H__

/* ==========================================================================
 * Internal: unique labels for continuation points (GCC addrlabels).
 * Not for direct use; merged into PT_BEGIN / PT_WAIT_UNTIL / PT_YIELD etc.
 * ========================================================================== */
#define PT_CONCAT2(s1, s2)   s1##s2
#define PT_CONCAT(s1, s2)    PT_CONCAT2(s1, s2)

/** Resume continuation for \a pt if set; otherwise fall through. */

#define PT_RESUME(pt) \
  do { \
    if ((pt)->lc != NULL) \
      goto *(pt)->lc; \
  } while (0)

/** Set continuation for \a pt at current line. */
#define PT_SET(pt) \
  do { \
    PT_CONCAT(PT_LABEL, __LINE__): \
    (pt)->lc = &&PT_CONCAT(PT_LABEL, __LINE__); \
  } while (0)

/* ==========================================================================
 * Protothread control structure
 * ========================================================================== */

/** Protothread state. Only the PT_* macros should touch \a lc. */
struct pt {
  void *lc;  /**< Continuation (GCC label pointer); NULL = start. */
};

/** Return values from a protothread function. */
#define PT_WAITING  0  /**< Blocked waiting. */
#define PT_YIELDED  1  /**< Yielded voluntarily. */
#define PT_EXITED   2  /**< Exited (PT_EXIT). */
#define PT_ENDED    3  /**< Reached PT_END. */

/**
 * \name Initialization
 * @{
 */

/**
 * Initialize a protothread.
 * Must be called before the first PT_SCHEDULE of this protothread.
 * \param pt  Pointer to the protothread control structure.
 */
#define PT_INIT(pt)  ((pt)->lc = NULL)

/** @} */

/**
 * \name Declaration and definition
 * @{
 */

/**
 * Declare a protothread function.
 * Use as the function return type, e.g. PT_THREAD(worker(struct pt *pt)).
 * \param name_args  Function name and parameter list.
 */
#define PT_THREAD(name_args)  char name_args

/**
 * Start of a protothread body.
 * Place at the top of the function; statements above are run every schedule.
 * Opens a block; PT_END closes it. PT_YIELD_FLAG is in scope between them.
 * \param pt  Pointer to the protothread control structure.
 */
#define PT_BEGIN(pt)  { char PT_YIELD_FLAG = 1; (void)PT_YIELD_FLAG; PT_RESUME((pt))

/**
 * End of a protothread.
 * Closes the block opened by PT_BEGIN and returns PT_ENDED.
 * \param pt  Pointer to the protothread control structure.
 */
#define PT_END(pt)  PT_INIT(pt); PT_YIELD_FLAG = 0; return PT_ENDED; }

/** @} */

/**
 * \name Blocked wait
 * @{
 */

/**
 * Block until \a condition is true.
 * \param pt         Pointer to the protothread control structure.
 * \param condition  Expression; protothread resumes when it is non-zero.
 */
#define PT_WAIT_UNTIL(pt, condition) \
  do { \
    PT_SET(pt); \
    if (!(condition)) \
      return PT_WAITING; \
  } while (0)

/**
 * Block while \a cond is true (i.e. until !(cond)).
 * \param pt    Pointer to the protothread control structure.
 * \param cond  Expression.
 */
#define PT_WAIT_WHILE(pt, cond)  PT_WAIT_UNTIL((pt), !(cond))

/** @} */

/**
 * \name Hierarchical protothreads
 * @{
 */

/**
 * Block until child protothread \a thread completes.
 * The child must be initialized with PT_INIT before use.
 * \param pt      Pointer to the parent protothread control structure.
 * \param thread  Child protothread call, e.g. child_pt(&pt_child).
 */
#define PT_WAIT_THREAD(pt, thread)  PT_WAIT_WHILE((pt), PT_SCHEDULE(thread))

/**
 * Spawn a child protothread and wait until it exits.
 * Initializes the child and waits; use within a protothread only.
 * \param pt     Pointer to the parent protothread control structure.
 * \param child  Pointer to the child's struct pt.
 * \param thread Child protothread call, e.g. child_fn(child).
 */
#define PT_SPAWN(pt, child, thread) \
  do { \
    PT_INIT((child)); \
    PT_WAIT_THREAD((pt), (thread)); \
  } while (0)

/** @} */

/**
 * \name Exiting and restarting
 * @{
 */

/**
 * Restart the protothread from PT_BEGIN.
 * \param pt  Pointer to the protothread control structure.
 */
#define PT_RESTART(pt) \
  do { \
    PT_INIT(pt); \
    return PT_WAITING; \
  } while (0)

/**
 * Exit the protothread.
 * If it was spawned, the parent becomes unblocked.
 * \param pt  Pointer to the protothread control structure.
 */
#define PT_EXIT(pt) \
  do { \
    PT_INIT(pt); \
    return PT_EXITED; \
  } while (0)

/** @} */

/**
 * \name Scheduling
 * @{
 */

/**
 * Schedule a protothread.
 * \param f  Call to the protothread function, e.g. my_pt(&pt_state).
 * \return  Non-zero if still running, 0 if exited or ended.
 */
#define PT_SCHEDULE(f)  ((f) < PT_EXITED)

/** @} */

/**
 * \name Yielding
 * @{
 */

/**
 * Yield once, then continue.
 * \param pt  Pointer to the protothread control structure.
 */
#define PT_YIELD(pt) \
  do { \
    PT_YIELD_FLAG = 0; \
    PT_SET(pt); \
    if (PT_YIELD_FLAG == 0) \
      return PT_YIELDED; \
  } while (0)

/**
 * Yield until \a cond is true.
 * \param pt   Pointer to the protothread control structure.
 * \param cond Expression; protothread continues when it is non-zero.
 */
#define PT_YIELD_UNTIL(pt, cond) \
  do { \
    PT_YIELD_FLAG = 0; \
    PT_SET(pt); \
    if ((PT_YIELD_FLAG == 0) || !(cond)) \
      return PT_YIELDED; \
  } while (0)

/** @} */

/* ===========================================================================
 * Counting semaphores (pt-sem)
 * =========================================================================== */

/**
 * Counting semaphore for use with protothreads.
 * Wait blocks while count is 0; signal increments count.
 */
struct pt_sem {
  unsigned int count;
};

/**
 * Initialize a semaphore.
 * \param s  Pointer to the semaphore.
 * \param c  Initial count (unsigned).
 */
#define PT_SEM_INIT(s, c)  ((s)->count = (c))

/**
 * Wait for the semaphore (decrement when > 0).
 * Blocks the protothread while count is 0.
 * \param pt  Pointer to the protothread control structure.
 * \param s   Pointer to the semaphore.
 */
#define PT_SEM_WAIT(pt, s) \
  do { \
    PT_WAIT_UNTIL(pt, (s)->count > 0); \
    (s)->count--; \
  } while (0)

/**
 * Signal the semaphore (increment count).
 * \param pt  Pointer to the protothread control structure (unused; for API consistency).
 * \param s   Pointer to the semaphore.
 */
#define PT_SEM_SIGNAL(pt, s)  ((s)->count++)

/* ===========================================================================
 * EXAMPLES (for reference; block not compiled when header is included)
 * ===========================================================================
 *
 * Example 1: Minimal protothread
 *
 *   #include "pt.h"
 *
 *   static struct pt pt_worker;
 *
 *   static PT_THREAD(worker(struct pt *pt))
 *   {
 *     PT_BEGIN(pt);
 *     while (1) {
 *       do_something();
 *       PT_WAIT_UNTIL(pt, data_ready());
 *       process(data);
 *     }
 *     PT_END(pt);
 *   }
 *
 *   int main(void)
 *   {
 *     PT_INIT(&pt_worker);
 *     while (PT_SCHEDULE(worker(&pt_worker)))
 *       ;
 *     return 0;
 *   }
 *
 * Example 2: Producer-consumer with semaphores (bounded buffer)
 *
 *   #include "pt.h"
 *
 *   #define NUM_ITEMS  32
 *   #define BUFSIZE    8
 *
 *   static struct pt_sem mutex, full, empty;
 *   static struct pt pt_producer, pt_consumer, pt_driver;
 *
 *   static PT_THREAD(producer(struct pt *pt))
 *   {
 *     static unsigned int produced;
 *
 *     PT_BEGIN(pt);
 *     for (produced = 0; produced < NUM_ITEMS; produced++) {
 *       PT_SEM_WAIT(pt, &full);
 *       PT_SEM_WAIT(pt, &mutex);
 *       add_to_buffer(produce_item());
 *       PT_SEM_SIGNAL(pt, &mutex);
 *       PT_SEM_SIGNAL(pt, &empty);
 *     }
 *     PT_END(pt);
 *   }
 *
 *   static PT_THREAD(consumer(struct pt *pt))
 *   {
 *     static unsigned int consumed;
 *
 *     PT_BEGIN(pt);
 *     for (consumed = 0; consumed < NUM_ITEMS; consumed++) {
 *       PT_SEM_WAIT(pt, &empty);
 *       PT_SEM_WAIT(pt, &mutex);
 *       consume_item(get_from_buffer());
 *       PT_SEM_SIGNAL(pt, &mutex);
 *       PT_SEM_SIGNAL(pt, &full);
 *     }
 *     PT_END(pt);
 *   }
 *
 *   static PT_THREAD(driver_thread(struct pt *pt))
 *   {
 *     PT_BEGIN(pt);
 *
 *     PT_SEM_INIT(&empty, 0);
 *     PT_SEM_INIT(&full, BUFSIZE);
 *     PT_SEM_INIT(&mutex, 1);
 *
 *     PT_INIT(&pt_producer);
 *     PT_INIT(&pt_consumer);
 *
 *     PT_WAIT_THREAD(pt, producer(&pt_producer) & consumer(&pt_consumer));
 *
 *     PT_END(pt);
 *   }
 *
 *   int main(void)
 *   {
 *     PT_INIT(&pt_driver);
 *     while (PT_SCHEDULE(driver_thread(&pt_driver)))
 *       ;
 *     return 0;
 *   }
 *
 *   Note: producer(&pt_producer) & consumer(&pt_consumer) runs both threads
 *   each schedule round and blocks until both have exited (return value
 *   >= PT_EXITED). Implement add_to_buffer, get_from_buffer, produce_item,
 *   consume_item, and the buffer as needed.
 *
 * Example 3: Spawning a child protothread
 *
 *   static struct pt pt_parent, pt_child;
 *
 *   static PT_THREAD(child(struct pt *pt))
 *   {
 *     PT_BEGIN(pt);
 *     do_work();
 *     PT_END(pt);
 *   }
 *
 *   static PT_THREAD(parent(struct pt *pt))
 *   {
 *     PT_BEGIN(pt);
 *     PT_SPAWN(pt, &pt_child, child(&pt_child));
 *     PT_END(pt);
 *   }
 *
 *   int main(void)
 *   {
 *     PT_INIT(&pt_parent);
 *     while (PT_SCHEDULE(parent(&pt_parent)))
 *       ;
 *     return 0;
 *   }
 *
 * Example 4: Yielding
 *
 *   static PT_THREAD(periodic(struct pt *pt))
 *   {
 *     PT_BEGIN(pt);
 *     for (;;) {
 *       do_work();
 *       PT_YIELD(pt);
 *     }
 *     PT_END(pt);
 *   }
 *
 *   PT_YIELD(pt) runs one step then yields; the scheduler can run other
 *   threads. PT_YIELD_UNTIL(pt, cond) yields until cond is true.
 */

#endif /* __PT_H__ */
