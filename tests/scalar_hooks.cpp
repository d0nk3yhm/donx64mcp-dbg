#include <windows.h>
#include <cstdint>
#include <iostream>
#include <utility>
template<size_t> using Word = std::uint64_t;
template<size_t... I>
__declspec(noinline) std::uint64_t function(Word<I>... args) {
    const auto incoming=GetLastError();
    const std::uint64_t values[]={args...,0};
    std::uint64_t result=incoming;
    for(size_t i=0;i<sizeof...(I);++i)result+=(i+1)*values[i];
    SetLastError(8765);
    return result;
}
template<size_t... I> std::uintptr_t address(std::index_sequence<I...>) {
    return reinterpret_cast<std::uintptr_t>(&function<I...>);
}
template<size_t... I> std::uint64_t invoke(std::index_sequence<I...>) {
    return function<I...>(std::uint64_t(I+1)...);
}
template<size_t... N> void addresses(std::index_sequence<N...>) {
    const std::uintptr_t entries[]={address(std::make_index_sequence<N>{})...};
    std::cout<<"ready "<<GetCurrentProcessId()<<std::hex;
    for(auto entry:entries)std::cout<<' '<<entry;
    std::cout<<std::dec<<std::endl;
}
template<size_t N=0> std::uint64_t dispatch(int count) {
    if(count==N)return invoke(std::make_index_sequence<N>{});
    if constexpr(N<16)return dispatch<N+1>(count);
    return 0;
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    addresses(std::make_index_sequence<17>{});
    int count;
    while(std::cin>>count && count>=0) {
        SetLastError(4321);
        const auto result=dispatch(count);
        const auto error=GetLastError();
        std::cout<<result<<' '<<error<<std::endl;
    }
}
