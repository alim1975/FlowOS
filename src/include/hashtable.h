#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

#define DEFAULT_TABLE_SIZE 64

struct node{
  char *key;
  void *value;
  struct node *next;
};
struct hashtable{
  int size;
  struct node **table;
};

int hashtable_create(struct hashtable *htable, int size);
void hashtable_destroy(struct hashtable *htable);
void hashtable_insert(struct hashtable *htable, char *key, void *value);
void hashtable_remove(struct hashtable *htable, char *key);
void *hashtable_get(struct hashtable *htable, char *key);
unsigned short hash_function(char *key);

#endif
