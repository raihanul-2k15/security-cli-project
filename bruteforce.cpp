#include "./include/constants.h"
#include<iostream>
#include<fstream>
#include<queue>
#include "./include/bruteforce.h"
using namespace std;

bool valid(string s) {
    bool u = false, l = false, d = false;
    for (int i = 0; i < s.size(); i++) {
        if (s[i] >= 'a' && s[i] <= 'z') l = true;
        else if (s[i] >= 'A' && s[i] <= 'Z') u = true;
        else if (s[i] >= '0' && s[i] <= '9') d = true;
    }
    return u && l && d;
}

int bruteforce_pass_gen(const char* chars, int min_len, int max_len, const char* file) {
    string charset(chars);
    
    for (int i = 0; i < charset.size(); i++)
        if (charset[i] >= 'a' && charset[i] <= 'z') charset += (charset[i] - ('a' - 'A'));
    
    int total = 0;
    ofstream fout(file);
    queue<string> q;
    q.push("");
    while(!q.empty()) {
        string u = q.front();
        q.pop();
        if (u.size() == max_len) continue;
        for (int i = 0; i < charset.size(); i++) {
            string v = u + charset[i];
            if (v.size() >= min_len && valid(v)) {
                total++;
                fout << v << endl;
            }
            q.push(v);
        }
    }
    cout << total << " passwords generated" << endl;

    fout.close();
    return 0;
}