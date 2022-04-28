from datetime import datetime, timedelta

class CADICache:
    CACHE_DICT = {}

    @staticmethod
    def set(key, value, expire):
        CADICache.CACHE_DICT[key] = (value, datetime.now() + timedelta(seconds=expire))

        # expire existing entries
        for k, v in list(CADICache.CACHE_DICT.items()):
            if v[1] < datetime.now():
                CADICache.CACHE_DICT.pop(k)

    @staticmethod
    def get(key, default=None):
        print(key)
        if key in CADICache.CACHE_DICT:
            value, expire = CADICache.CACHE_DICT[key]
            if expire > datetime.now():
                return value
        return default

    @staticmethod
    def delete(key):
        if key in CADICache.CACHE_DICT:
            del CADICache.CACHE_DICT[key]

    @staticmethod
    def insert_into_list(key, item, max_entries, expire, replace_by_key=None):
        list_ = CADICache.get(key, default=[])
        if replace_by_key is not None:
            for i, entry in list(enumerate(list_)):
                if entry == replace_by_key:
                    del list_[i]
                    break

        list_.append(item)

        list_ = list_[:max_entries]
        CADICache.set(key, list_, expire)


# # For Memcache
# 
# 
# MAX_RETRIES_CHECK_AND_SET = 7
# 
# 
# def insert_into_cache_list(cache, key, item, max_entries, expire, replace_by_key=None):
#     for i in range(MAX_RETRIES_CHECK_AND_SET):
#         # Retry loop, limited to some reasonable retries
#         the_list, cas_key = cache.gets(key)
#         if the_list is None:
#             the_list = [item]
#             cache.set(key, the_list, expire=expire)
#             return
#         else:
#             if replace_by_key:
#                 for e in the_list:
#                     if getattr(e, replace_by_key) == getattr(item, replace_by_key):
#                         the_list.remove(e)
# 
#             # Insert latest result on the top
#             the_list.insert(0, item)
# 
#             # Truncate the list to the max number of results
#             the_list = the_list[:max_entries]
# 
#             if cache.cas(key, the_list, expire=expire, cas=cas_key):
#                 return
# 
#     raise Exception("Could not insert data item into cache")
# 
# 