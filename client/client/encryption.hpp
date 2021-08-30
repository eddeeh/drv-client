#pragma once
#pragma warning( disable : 4172 )
#include <array>

// Credits: kwezee

namespace encryption
{
	template< class _t, const size_t _s, const _t _k = 'L' >
	class xstr {
		std::array< _t, _s > buffer;

		constexpr auto enc(const _t ch) const noexcept -> _t {
			return ch ^ _k;
		}

		auto dec(const _t ch) const noexcept -> _t {
			return ch ^ _k;
		}

	public:
		auto data() noexcept {
			for (auto i = _s; i--; ) {
				buffer[i] = dec(buffer[i]);
			}

			return buffer.data();
		}

		template< size_t... _i >
		constexpr __forceinline xstr(const _t(&s)[_s], std::index_sequence< _i... >) noexcept
			: buffer{ enc(s[_i])... } {}
	};

	template< class _t, size_t _s >
	constexpr __forceinline auto XorString(const _t(&s)[_s]) {
		return xstr< _t, _s >{ s, std::make_index_sequence< _s >() }.data();
	}
}