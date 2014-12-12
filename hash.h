/* Copyright 2014 Damian Jarek
    This file is part of md5lamacz.

    md5lamacz is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    md5lamacz is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with md5lamacz.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __HASH_H__
#define __HASH_H__

#include <openssl/md5.h>
#include <ostream>
#include <unordered_map>

class Hash
{
public:
  Hash();
  Hash(const std::string& password);

  bool operator==(const Hash& other) const;

  static Hash storeHash(const std::string& passwordHash);

  friend std::ostream& operator<<(std::ostream& output, const Hash& input);
  friend struct HashMapFunctor;
private:
  uint64_t hash[2];
};

struct HashMapFunctor //funktor hashujacy Hashe dla tablicy hashujacej #incepcja
{
  size_t operator()(const Hash& h) const
  {
    return h.hash[0] xor h.hash[1];
  }
};

typedef std::unordered_multimap<Hash, std::string, HashMapFunctor> PasswordMap;

std::string& toLower(std::string& str);
std::string& toUpper(std::string& str);

#endif //__HASH_H__