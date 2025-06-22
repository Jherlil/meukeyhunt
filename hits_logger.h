#ifndef HITS_LOGGER_H
#define HITS_LOGGER_H

#include <string>

void log_hit(const std::string &priv, const std::string &wif, const std::string &pub, const std::string &addr, int score);
void export_hits(const std::string &filename_csv);
void export_hits_json(const std::string &filename_json);

#endif
