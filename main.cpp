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

#include <vector>
#include <mutex>
#include <atomic>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <set>
#include <iostream>

#include "hash.h"
#include "thread_manager.h"

typedef std::vector<std::string> DictionaryVec;
typedef DictionaryVec::const_iterator DictionaryIterator;

typedef std::vector<std::thread> ThreadVec;
typedef std::pair<std::string, Hash> ProducedHashPair;
typedef std::function<ProducedHashPair(const DictionaryVec& vec, const DictionaryIterator& it, const uint64_t& round)> SingleWordFunctor;

DictionaryVec dictionary;

void loadPasswords(const std::string& fileName, PasswordMap& map)
{
  std::ifstream inputFile(fileName);
  uint64_t id = 0;
  std::string email, passwordHash;

  inputFile >> id >> email >> passwordHash;
  while(inputFile.good()) {
    map.insert(std::make_pair(Hash::storeHash(passwordHash), std::move(email)));
    inputFile >> id >> email >> passwordHash;
  }
}

void loadDictionary(const std::string& fileName)
{
  dictionary.clear();
  std::ifstream inputFile(fileName);
  std::string word;
  std::set<std::string> passwordSet;

  inputFile >> word;
  toLower(word);
  while(inputFile.good()) {
    auto it = passwordSet.insert(word);
    if (it.second) {
      dictionary.emplace_back(std::move(word));
    }
    inputFile >> word;
    toLower(word);
  }
}

extern std::mutex foundPasswordsMtx;
extern std::atomic<uint64_t> n;
extern std::vector<ProducedHashPair> foundPasswords;

int main()
{
  PasswordMap passwordHashes;

  loadDictionary("slownik.txt");
  loadPasswords("baza.txt", passwordHashes);

  ThreadManager threadManager {passwordHashes};
  threadManager.launchProducers();
  std::this_thread::sleep_for(std::chrono::seconds(6));

  threadManager.stopProducers();

  std::lock_guard<std::mutex> lock(foundPasswordsMtx);
  for (const auto& foundPassword : foundPasswords) {
    auto range = passwordHashes.equal_range(foundPassword.second);
    std::for_each(
      range.first,
      range.second,
      [&foundPassword](PasswordMap::value_type& x){ std::cout << foundPassword.first << " "<< x.second << std::endl;}
    );
    //std::cout << std::endl;
  }
  std::cout << "hashow/s: " << n.load()/6.0 << std::endl;
  return 0;
}