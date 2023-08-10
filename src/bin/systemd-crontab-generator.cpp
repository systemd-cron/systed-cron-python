#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <pwd.h>
#include <regex.h>
#include <set>
#include <stdarg.h>
#include <string>
#include <string_view>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>
#if __has_include(<alloca.h>)
#include <alloca.h>
#endif

using namespace std::literals;

namespace vore::file {
	namespace {
		template <class C = char>
		class mapping {
		public:
			constexpr mapping() noexcept {}

			mapping(void * addr, std::size_t length, int prot, int flags, int fd, off_t offset) noexcept {
				void * ret = mmap(addr, length, prot, flags, fd, offset);
				if(ret != MAP_FAILED) {
					static_assert(sizeof(C) == 1);
					this->map    = {static_cast<C *>(ret), length};
					this->opened = true;
				}
			}

			mapping(const mapping &) = delete;
			constexpr mapping(mapping && oth) noexcept : map(oth.map), opened(oth.opened) { oth.opened = false; }

			constexpr mapping & operator=(mapping && oth) noexcept {
				this->map    = oth.map;
				this->opened = oth.opened;
				oth.opened   = false;
				return *this;
			}

			~mapping() {
				if(this->opened)
					munmap(const_cast<C *>(this->map.data()), this->map.size());
			}

			constexpr operator bool() const noexcept { return !this->map.empty(); }
			constexpr operator std::basic_string_view<C>() const noexcept { return this->map; }
			constexpr const std::basic_string_view<C> & operator*() const noexcept { return this->map; }
			constexpr const std::basic_string_view<C> * operator->() const noexcept { return &this->map; }


		private:
			std::basic_string_view<C> map = {};
			bool opened                   = false;
		};
	}
}

namespace vore {
	namespace {
		template <class CharT, class Traits>
		constexpr std::basic_string_view<CharT, Traits> basename(std::basic_string_view<CharT, Traits> str) noexcept {
			if(size_t idx = str.rfind('/'); idx != std::basic_string_view<CharT, Traits>::npos)
				str.remove_prefix(idx + 1);

			return std::move(str);
		}
	}
}


namespace vore::file {
	namespace {
		template <bool allow_stdio>
		class fd {
			template <bool as>
			friend class FILE;

		public:
			static constexpr fd<allow_stdio> faux(int desc) noexcept {
				fd<allow_stdio> ret;
				ret.desc   = desc;
				ret.opened = false;
				return ret;
			}
			static constexpr fd<allow_stdio> for_stdout() noexcept { return faux(1); }


			constexpr fd() noexcept = default;
			fd(const char * path, int flags, mode_t mode = 0, int from = AT_FDCWD) noexcept {
				if constexpr(allow_stdio)
					if(path[0] == '-' && !path[1]) {  // path == "-"sv but saves a strlen() call on libstdc++
						switch(flags & O_ACCMODE) {
							case O_RDONLY:
								this->desc = 0;
								return;
							case O_WRONLY:
								this->desc = 1;
								return;
							default:
								errno = EINVAL;
								return;
						}
					}

				while((this->desc = openat(from, path, flags, mode)) == -1 && errno == EINTR)
					;
				this->opened = this->desc != -1;
			}
			fd(int desc) noexcept : desc(desc), opened(true) {}

			fd(const fd &) = delete;
			constexpr fd(fd && oth) noexcept { *this = std::move(oth); }

			constexpr fd & operator=(fd && oth) noexcept {
				this->swap(oth);
				return *this;
			}

			~fd() {
				if(this->opened)
					close(this->desc);
			}

			constexpr operator int() const noexcept { return this->desc; }

			int take() & noexcept {
				this->opened = false;
				return this->desc;
			}

			constexpr void swap(fd & oth) noexcept {
				std::swap(this->desc, oth.desc);
				std::swap(this->opened, oth.opened);
			}

		private:
			int desc = -1;

		public:
			bool opened = false;
		};

		template <bool allow_stdio>
		class FILE {
		public:
			constexpr FILE() noexcept = default;

			FILE(const char * path, const char * opts) noexcept {
				if constexpr(allow_stdio)
					if(path[0] == '-' && !path[1]) {  // path == "-"sv but saves a strlen() call on libstdc++
						if(opts[0] && opts[1] == '+') {
							errno = EINVAL;
							return;
						}
						switch(opts[0]) {
							case 'r':
								this->stream = stdin;
								return;
							case 'w':
							case 'a':
								this->stream = stdout;
								return;
							default:
								errno = EINVAL;
								return;
						}
					}

				this->stream = std::fopen(path, opts);
				this->opened = this->stream;
			}

			FILE(const FILE &) = delete;
			constexpr FILE(FILE && oth) noexcept { *this = std::move(oth); }

			FILE(int oth, const char * opts) noexcept : stream(oth != -1 ? fdopen(oth, opts) : nullptr), opened(this->stream) {}
			FILE(fd<false> && oth, const char * opts) noexcept : FILE(static_cast<int>(oth), opts) {
				if(this->stream)
					oth.opened = false;
			}

			constexpr FILE & operator=(FILE && oth) noexcept {
				this->swap(oth);
				return *this;
			}

			~FILE() {
				if(this->opened)
					std::fclose(this->stream);
			}

			constexpr operator ::FILE *() const noexcept { return this->stream; }

			constexpr void swap(FILE & oth) noexcept {
				std::swap(this->stream, oth.stream);
				std::swap(this->opened, oth.opened);
			}

			constexpr ::FILE * leak() && noexcept {
				this->opened = false;
				return this->stream;
			}

		private:
			::FILE * stream = nullptr;
			bool opened     = false;
		};

		template <bool = false>
		FILE(fd<false> &&, const char *) -> FILE<false>;
	}
}
namespace vore::file {
	namespace {
		struct DIR_iter {
			::DIR * stream{};
			struct dirent * entry{};


			DIR_iter & operator++() noexcept {
				if(this->stream)
					do
						this->entry = readdir(this->stream);
					while(this->entry &&
					      ((this->entry->d_name[0] == '.' && this->entry->d_name[1] == '\0') ||  // this->entry == "."sv || this->entry == ".."sv, but saves trips to libc
					       (this->entry->d_name[0] == '.' && this->entry->d_name[1] == '.' && this->entry->d_name[2] == '\0')));
				return *this;
			}

			DIR_iter operator++(int) noexcept {
				const auto ret = *this;
				++(*this);
				return ret;
			}

			constexpr bool operator==(const DIR_iter & rhs) const noexcept { return this->entry == rhs.entry; }
			constexpr bool operator!=(const DIR_iter & rhs) const noexcept { return !(*this == rhs); }

			constexpr const dirent & operator*() const noexcept { return *this->entry; }
		};


		class DIR {
		public:
			using iterator = DIR_iter;


			DIR(const char * path) noexcept {
				this->stream = opendir(path);
				this->opened = this->stream;
			}

			DIR(int at, const char * path, int flags = 0) noexcept {
				if(auto fd = openat(at, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | flags); fd != -1)
					this->stream = fdopendir(fd);
				this->opened = this->stream;
			}

			DIR(const DIR &) = delete;
			constexpr DIR(DIR && oth) noexcept : stream(oth.stream), opened(oth.opened) { oth.opened = false; }

			~DIR() {
				if(this->opened)
					closedir(this->stream);
			}

			constexpr operator ::DIR *() const noexcept { return this->stream; }


			iterator begin() const noexcept { return ++iterator{this->stream}; }
			constexpr iterator end() const noexcept { return {}; }

		private:
			::DIR * stream = nullptr;
			bool opened    = false;
		};
	}
}

namespace vore {
	namespace {
		struct soft_tokenise_iter {  // merge_seps = true
			using iterator_category = std::input_iterator_tag;
			using difference_type   = void;
			using value_type        = std::string_view;
			using pointer           = std::string_view *;
			using reference         = std::string_view &;

			std::string_view delim;
			std::string_view remaining;
			std::string_view token = {};


			soft_tokenise_iter & operator++() noexcept {
				auto next = this->remaining.find_first_not_of(this->delim);
				if(next != std::string_view::npos)
					this->remaining.remove_prefix(next);
				auto len = this->remaining.find_first_of(this->delim);
				if(len != std::string_view::npos) {
					this->token = {this->remaining.data(), len};
					this->remaining.remove_prefix(len);
				} else {
					this->token     = this->remaining;
					this->remaining = {};
				}
				return *this;
			}

			soft_tokenise_iter operator++(int) noexcept {
				const auto ret = *this;
				++(*this);
				return ret;
			}

			constexpr bool operator==(const soft_tokenise_iter & rhs) const noexcept { return this->token == rhs.token; }
			constexpr bool operator!=(const soft_tokenise_iter & rhs) const noexcept { return !(*this == rhs); }

			constexpr std::string_view operator*() const noexcept { return this->token; }
		};


		struct soft_tokenise {
			using iterator = soft_tokenise_iter;


			std::string_view str;
			std::string_view delim;


			iterator begin() noexcept { return ++iterator{this->delim, this->str}; }
			constexpr iterator end() const noexcept { return {}; }
		};
	}
}


#ifndef strndupa
#define strndupa(str, maxlen)                                      \
	__extension__({                                                  \
		auto _strdupa_str = str;                                       \
		auto len          = strnlen(_strdupa_str, maxlen);             \
		auto ret          = reinterpret_cast<char *>(alloca(len + 1)); \
		std::memcpy(ret, _strdupa_str, len);                           \
		ret[len] = '\0';                                               \
		ret;                                                           \
	})
#endif


#define MAYBE_DUPA(strv)                                                       \
	__extension__({                                                              \
		auto && _strv = strv;                                                      \
		_strv[_strv.size()] ? strndupa(_strv.data(), _strv.size()) : _strv.data(); \
	})


namespace vore {
	namespace {
		template <int base = 0, class T>
		bool parse_uint(const char * val, T & out) {
			if(val[0] == '\0')
				return errno = EINVAL, false;
			if(val[0] == '-')
				return errno = ERANGE, false;

			char * end{};
			errno    = 0;
			auto res = std::strtoull(val, &end, base);
			out      = res;
			if(errno)
				return false;
			if(res > std::numeric_limits<T>::max())
				return errno = ERANGE, false;
			if(*end != '\0')
				return errno = EINVAL, false;

			return true;
		}
	}
}

namespace vore {
	namespace {
		template <class T>
		struct span {
			T b, e;

			constexpr T begin() const noexcept { return this->b; }
			constexpr T end() const noexcept { return this->e; }
			constexpr std::size_t size() const noexcept { return this->e - this->b; }
			constexpr decltype(*(T{})) & operator[](std::size_t i) const noexcept { return *(this->b + i); }
		};


		template <class T>
		span(T, T) -> span<T>;
	}
}

namespace vore {
	namespace {
		template <class I, class T>
		I binary_find(I begin, I end, const T & val) {  // std::binary_search() but returns the iterator instead
			begin = std::lower_bound(begin, end, val);
			return (!(begin == end) && !(val < *begin)) ? begin : end;
		}
		template <class I, class T, class Compare>
		I binary_find(I begin, I end, const T & val, Compare comp) {
			begin = std::lower_bound(begin, end, val, comp);
			return (!(begin == end) && !comp(val, *begin)) ? begin : end;
		}
	}
}

namespace vore {
	namespace {
		template <class... Ts>
		struct overload : Ts... {
			using Ts::operator()...;
		};
		template <class... Ts>
		overload(Ts...) -> overload<Ts...>;
	}
}
static const constexpr auto key_or_plain = [](auto && lhs, auto && rhs) {
	static const constexpr auto key =
	    vore::overload{[](const std::string_view & s) { return s; }, [](const std::pair<std::string_view, std::string_view> & kv) { return kv.first; }};
	return key(lhs) < key(rhs);
};


static const regex_t ENVVAR_RE = [] {
	regex_t ret;
	assert(!regcomp(&ret, R"regex(^([A-Za-z_0-9]+)[[:space:]]*=[[:space:]]*(.*)$)regex", REG_EXTENDED | REG_NEWLINE));
	assert(ret.re_nsub == 2);
	return ret;
}();

static const constexpr std::uint8_t MINUTES_SET[]  = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                                      20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                                                      40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59};
static const constexpr std::uint8_t HOURS_SET[]    = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23};
static const constexpr std::uint8_t DAYS_SET[]     = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                                      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
static const constexpr std::string_view DOWS_SET[] = {"Sun"sv, "Mon"sv, "Tue"sv, "Wed"sv, "Thu"sv, "Fri"sv, "Sat"sv, "Sun"sv};
static const constexpr std::uint8_t MONTHS_SET[]   = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

static const constexpr std::string_view KSH_SHELLS[] = {"bash"sv, "dash"sv, "ksh"sv, "sh"sv, "zsh"sv};  // keep sorted
static const char * const REBOOT_FILE                = "/run/crond.reboot";

static const constexpr std::string_view USE_LOGLEVELMAX = "@use_loglevelmax@"sv;
static const constexpr bool USE_RUNPARTS                = false;  // "@use_runparts@" == "True";  // TODO
static const constexpr std::string_view BOOT_DELAY      = "@libexecdir@/systemd-cron/boot_delay"sv;
#define STATEDIR "@statedir@"

static const char * SELF;
static bool RUN_BY_SYSTEMD;
static const constexpr std::string_view VALID_CHARS = "-"
                                                      "0123456789"
                                                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                      "_"
                                                      "abcdefghijklmnopqrstuvwxyz"sv;  // keep sorted


// this is dumb, but gets the job done
static const constexpr std::pair<std::string_view, std::string_view> PART2TIMER[] = {
    {"apt-compat"sv, "apt-daily"sv},
    {"dpkg"sv, "dpkg-db-backup"sv},
    {"plocate"sv, "plocate-updatedb"sv},
    {"sysstat"sv, "sysstat-summary"sv},
};

static const constexpr std::pair<std::string_view, std::string_view> CROND2TIMER[] = {
    {"ntpsec"sv, "ntpsec-rotate-stats"sv},
    {"ntpsec-ntpviz"sv, "ntpviz-daily"sv},
    {"sysstat"sv, "sysstat-collect"sv},
};

static auto which(const std::string_view & exe, std::optional<std::string_view> paths = {}) -> std::optional<std::string> {
	if(!paths)
		paths = std::getenv("PATH") ?: "/usr/bin:/bin";
	for(auto path : vore::soft_tokenise{*paths, ":"sv}) {
		auto abspath = (std::string{path} += '/') += exe;
		if(!access(abspath.c_str(), X_OK))
			return abspath;
	}
	return {};
}

static const bool HAS_SENDMAIL = static_cast<bool>(which("sendmail", "/usr/sbin:/usr/lib"sv));
static std::string_view TARGET_DIR;
static std::string TIMERS_DIR;
static std::optional<std::uint64_t> UPTIME;

static auto systemd_bool(const std::string_view & string) -> bool {
	return strncasecmp(string.data(), "1", string.size()) ||    //
	       strncasecmp(string.data(), "yes", string.size()) ||  //
	       strncasecmp(string.data(), "true", string.size());
}

enum class Log : std::uint8_t { EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG };
static __attribute__((format(printf, 2, 3))) void log(Log level, const char * fmt, ...) {
	va_list args;
	va_start(args, fmt);

	auto into = stderr;
	vore::file::FILE<false> kmsg;
	if(RUN_BY_SYSTEMD && (kmsg = {"/dev/kmsg", "we"})) {
		std::fprintf(kmsg, "<%" PRIu8 ">%s[%d]", static_cast<std::uint8_t>(level), SELF, getpid());
		into = kmsg;
	} else
		std::fputs(SELF, into);
	std::fputs(": ", into);
	std::vfprintf(into, fmt, args);
	std::fputc('\n', into);
	va_end(args);
}
#define FORMAT_SV(sv) (int)(sv).size(), (sv).data()


static auto int_map(const std::string_view & str, bool & err) -> std::size_t;
static auto month_map(const std::string_view & month, bool & err) -> std::size_t;
static auto dow_map(const std::string_view & dow_full, bool & err) -> std::size_t;
template <class T, class V>
static auto parse_period(const std::string_view & value, const V & values, std::set<T> & into, std::size_t (*mapping)(const std::string_view &, bool &),
                         std::size_t base) -> bool;
static auto environment_write(const std::map<std::string_view, std::string_view> & env, FILE * into) -> void;

struct Job {
	std::string filename;
	std::string_view basename;
	std::string_view line;
	std::vector<std::string_view> parts;
	std::map<std::string_view, std::string_view> environment;
	std::string environment_PATH_storage;  // borrowed into environment on expansion
	std::string_view shell;
	std::size_t random_delay;
	std::string period;                       // either period or timespec
	std::set<std::uint8_t> timespec_minute;   // 0-60
	std::set<std::uint8_t> timespec_hour;     // 0-24
	std::set<std::uint8_t> timespec_dom;      // 0-31
	std::set<std::string_view> timespec_dow;  // 0-7 (actually sun-mon-...-sun)
	std::set<std::uint8_t> timespec_month;    // 0-12
	bool sunday_is_seven;
	std::string schedule;
	std::size_t boot_delay;
	std::size_t start_hour;
	bool persistent;
	bool batch;
	std::string jobid;  // should be cow
	std::string unit_name;
	std::string_view user;
	std::optional<std::string> home;
	struct {
		vore::span<const std::string_view *> command;  // subview of parts
		std::optional<std::string> command0;           // except this is command[0] if set

		struct command_iter {
			using iterator_category = std::input_iterator_tag;
			using difference_type   = void;
			using value_type        = const std::string_view;
			using pointer           = const std::string_view *;
			using reference         = const std::string_view &;

			vore::span<const std::string_view *> command;
			std::optional<std::string_view> command0;

			command_iter & operator++() noexcept {
				if(this->command.size())
					this->command0 = *command.b++;
				else
					this->command0 = {};
				return *this;
			}

			constexpr bool operator==(const command_iter & rhs) const noexcept { return this->command0 == rhs.command0 && this->command.b == rhs.command.b; }
			constexpr bool operator!=(const command_iter & rhs) const noexcept { return !(*this == rhs); }

			constexpr const std::string_view & operator*() const noexcept { return *this->command0; }
		};

		constexpr command_iter begin() const noexcept { return {this->command, this->command0}; }
		constexpr command_iter end() const noexcept { return {{this->command.e, this->command.e}, {}}; }
		constexpr std::size_t size() const noexcept { return this->command.size() + static_cast<bool>(this->command0); }
		constexpr std::string_view operator[](std::size_t i) const noexcept {
			if(this->command0) {
				if(!i)
					return *this->command0;
				--i;
			}
			return this->command[i];
		}
	} command;
	std::string execstart;
	bool valid;
	std::optional<std::string_view> testremoved;  // view of line

	Job(std::string_view filename, std::string_view line) {
		this->filename = filename;
		this->basename = vore::basename(filename);
		this->line     = line;

		vore::soft_tokenise tokens{line, " \t\n"sv};
		std::copy(std::begin(tokens), std::end(tokens), std::back_inserter(this->parts));

		this->shell           = "/bin/sh"sv;
		this->boot_delay      = 0;
		this->start_hour      = 0;
		this->random_delay    = 0;
		this->persistent      = false;
		this->user            = "root"sv;
		this->command         = {};
		this->valid           = true;
		this->batch           = false;
		this->sunday_is_seven = false;
	}

	auto log(Log priority, const char * message) -> void { ::log(priority, "%s in %.*s:%.*s", message, FORMAT_SV(this->filename), FORMAT_SV(this->line)); }

	auto which(const std::string_view & pgm) -> std::optional<std::string> {
		auto itr = this->environment.find("PATH"sv);
		return ::which(pgm, itr == std::end(this->environment) ? std::nullopt : std::optional{itr->second});
	}

	// decode some environment variables that influence the behaviour of systemd-cron itself
	auto decode_environment(const std::map<std::string_view, std::string_view> & environment, bool default_persistent) -> void {
		this->persistent = default_persistent;
		for(auto && [k, v] : environment) {
			if(k == "PERSISTENT"sv)
				this->persistent = systemd_bool(v);
			else if(k == "RANDOM_DELAY"sv) {
				bool err{};
				this->random_delay = int_map(v, err);
				if(err)
					this->log(Log::WARNING, "invalid RANDOM_DELAY");
			} else if(k == "START_HOURS_RANGE"sv) {
				bool err{};
				this->start_hour = int_map(v, err);
				if(err)
					this->log(Log::WARNING, "invalid START_HOURS_RANGE");
			} else if(k == "DELAY"sv) {
				bool err{};
				this->boot_delay = int_map(v, err);
				if(err)
					this->log(Log::WARNING, "invalid DELAY");
			} else if(k == "BATCH"sv) {
				this->batch = systemd_bool(v);
			} else {
				if(k == "SHELL"sv)
					this->shell = v;

				if(k == "MAILTO"sv && !v.empty())
					if(!HAS_SENDMAIL)
						this->log(Log::WARNING, "a MTA is not installed, but MAILTO is set");

				this->environment.emplace(k, v);
			}
		}
	}

	auto parse_anacrontab() -> void {
		if(this->parts.size() < 4) {
			this->valid = false;
			return;
		}

		this->period = this->parts[0];
		this->jobid  = "anacron-"s += this->parts[2];
		bool err{};
		this->boot_delay = int_map(this->parts[1], err);
		if(err)
			this->log(Log::WARNING, "invalid DELAY");
		this->command.command.b = &*(this->parts.begin() + 3);
		this->command.command.e = &*(this->parts.end());
	}

	/*def parse_crontab_auto() -> None:
	    '''crontab --translate <something>'''
	    if this->line.startswith('@'):
	        this->parse_crontab_at(false)
	    else:
	        this->parse_crontab_timespec(false)

	    if (this->command.size()) {
	        if (this->command.size() > 1) {
	            auto maybe_user = this->command[0];
	            try:
	                pwd.getpwnam(maybe_user)
	                this->user = maybe_user
	                ++this->command.bZ
	            except:
	                this->user = os.getlogin()
	        } else
	            this->user = os.getlogin()

	        pgm = this->which(this->command[0])
	        if (pgm)
	            this->command[0] = pgm;
	        this->execstart = ' '.join(this->command)
	    }*/

	// @daily (user) do something
	auto parse_crontab_at(bool withuser) -> void {
		if(this->parts.size() < (2 + withuser)) {
			this->valid = false;
			return;
		}

		this->period = this->parts[0];
		if(withuser) {
			this->user              = this->parts[1];
			this->command.command.b = &*(this->parts.begin() + 2);
		} else {
			this->user              = this->basename;
			this->command.command.b = &*(this->parts.begin() + 1);
		}
		this->command.command.e = &*(this->parts.end());
		this->jobid             = (std::string{this->basename} += '-') += this->user;
	}

	// 6 2 * * * (user) do something
	auto parse_crontab_timespec(bool withuser) -> void {
		if(this->parts.size() < (6 + withuser)) {
			this->valid = false;
			return;
		}

		auto && minutes       = this->parts[0];
		auto && hours         = this->parts[1];
		auto && days          = this->parts[2];
		auto && months        = this->parts[3];
		auto && dows          = this->parts[4];
		this->timespec_minute = this->parse_time_unit<false, std::uint8_t>(minutes, MINUTES_SET, int_map);
		this->timespec_hour   = this->parse_time_unit<false, std::uint8_t>(hours, HOURS_SET, int_map);
		this->timespec_dom    = this->parse_time_unit<false, std::uint8_t>(days, DAYS_SET, int_map);
		this->timespec_dow    = this->parse_time_unit<true, std::string_view>(dows, DOWS_SET, dow_map);
		this->timespec_month  = this->parse_time_unit<false, std::uint8_t>(months, MONTHS_SET, month_map);

		this->sunday_is_seven = dows.back() == '7' || [&] {
			if(dows.size() < 3)
				return false;
			char buf[3]{};
			std::transform(std::end(dows) - 3, std::end(dows), buf, ::tolower);
			return std::string_view{buf, 3} == "sun"sv;
		}();

		if(withuser) {
			this->user              = this->parts[5];
			this->command.command.b = &*(this->parts.begin() + 6);
		} else {
			this->user              = this->basename;
			this->command.command.b = &*(this->parts.begin() + 5);
		}
		this->command.command.e = &*(this->parts.end());
		this->jobid             = (std::string{this->basename} += '-') += this->user;
	}

	static const constexpr std::uint8_t TIMESPEC_ASTERISK = -1;
	template <bool DOW, class T, class V>
	auto parse_time_unit(const std::string_view & value, const V & values, std::size_t (*mapping)(const std::string_view &, bool &)) -> std::set<T> {
		if(value == "*"sv) {
			if constexpr(DOW)
				return {"*"sv};
			else
				return {TIMESPEC_ASTERISK};
		}

		std::size_t base;
		if constexpr(DOW)
			base = 0;
		else
			base = *std::min_element(std::begin(values), std::end(values));

		std::set<T> result;
		// TODO: wrong split! :                 map(parse_period(mapping, base), value.split(','))
		for(auto && subval : vore::soft_tokenise{value, ","sv})
			if(!parse_period(subval, values, result, mapping, base)) {
				this->log(Log::ERR, "garbled time");
				this->valid = false;
				return {};
			}
		return result;
	}

	// decode & validate
	auto decode() -> void {
		this->jobid.erase(std::remove_if(std::begin(this->jobid), std::end(this->jobid),
		                                 [](char c) { return !std::binary_search(std::begin(VALID_CHARS), std::end(VALID_CHARS), c); }),
		                  std::end(this->jobid));
		this->decode_command();
	}

	// perform smart substitutions for known shells
	auto decode_command() -> void {
		if(!this->home) {
			static std::map<std::string, std::string, std::less<>> pwnam_cache;
			auto itr = pwnam_cache.find(this->user);
			if(itr == std::end(pwnam_cache)) {
				std::string user{this->user};
				if(auto ent = getpwnam(user.data()))
					itr = pwnam_cache.emplace(std::move(user), ent->pw_dir).first;
			}
			if(itr != std::end(pwnam_cache))
				this->home = itr->second;
		}

		if(this->home) {
			if(this->command[0].starts_with("~/"sv)) {
				*(this->command.command0 = *this->home) += this->command[0].substr(1);
				++this->command.command.b;
			}

			if(auto itr = this->environment.find("PATH"sv); itr != std::end(this->environment))
				if(itr->second.starts_with("~/") || itr->second.find(":~/"sv) != std::string_view::npos) {
					for(auto && path : vore::soft_tokenise{itr->second, ":"sv}) {
						if(path.starts_with("~/")) {
							this->environment_PATH_storage += *this->home;
							this->environment_PATH_storage += path.substr(1);
						} else
							this->environment_PATH_storage += path;
						this->environment_PATH_storage += ':';
					}
					this->environment_PATH_storage.pop_back();
					this->environment["PATH"sv] = this->environment_PATH_storage;
				}
		}

		if(!std::binary_search(std::begin(KSH_SHELLS), std::end(KSH_SHELLS), vore::basename(this->shell)))
			return;

		if(auto pgm = this->which(this->command[0]); pgm && *pgm != this->command[0]) {
			if(!this->command.command0)
				++this->command.command.b;
			this->command.command0 = std::move(pgm);
		}

		/*if(this->command.size() >= 3 && this->command[-2] == '>' && this->command[-1] == '/dev/null')
		  this->command = this->command [0:-2];

		if(this->command.size() >= 2 && this->command[-1] == '>/dev/null')
		  this->command = this->command [0:-1];

		if(this->command.size() == 6 && this->command[0] == '[' && this->command[1] in['-x', '-f', '-e'] && this->command[2] == this->command[5] &&
		   this->command[3] == ']' && this->command[4] == '&&') {
		  this->testremoved = this->command[2];
		  this->command     = this->command [5:];
		}

		if(this->command.size() == 5 && this->command[0] == 'test' && this->command[1] in['-x', '-f', '-e'] && this->command[2] == this->command[4] &&
		   this->command[3] == '&&') {
		  this->testremoved = this->command[2];
		  this->command     = this->command [4:];
		}*/
	}

	auto is_active() -> bool {
		if(this->testremoved && access(MAYBE_DUPA(*this->testremoved), F_OK)) {  // TODO: NOTE: isfile -> access: this also handles -e
			::log(Log::NOTICE, "%.*s is removed, skipping job", FORMAT_SV(*this->testremoved));
			return false;
		}

		if(this->schedule == "reboot"sv && !access(REBOOT_FILE, F_OK))
			return false;

		//		if(len(this->command) == 6 && this->command[0] == '[' && this->command[1] in['-d', '-e'] && this->command[2].startswith('/run/systemd') &&
		//		   this->command[3] == ']' && this->command[4] == '||')
		//			return false;
		//
		//		if(len(this->command) == 5 && this->command[0] == 'test' && this->command[1] in['-d', '-e'] && this->command[2].startswith('/run/systemd') &&
		//		   this->command[3] == '||')
		//			return false;

		return true;
	}

	auto generate_schedule_from_period() -> void {
		static const constexpr std::string_view TIME_UNITS_SET[] = {"daily"sv,         "monthly"sv, "quarterly"sv,
		                                                            "semi-annually"sv, "weekly"sv,  "yearly"sv};  // keep sorted

		if(auto i = this->period.find_first_not_of('@'); i != std::string::npos)
			this->period.erase(0, i);
		else
			this->period = {};
		std::transform(std::begin(this->period), std::end(this->period), std::begin(this->period), ::tolower);
		static const constexpr std::pair<std::string_view, std::string_view> replacements[] = {
		    // keep sorted
		    {"1"sv, "daily"sv},
		    {"30"sv, "monthly"sv},
		    {"31"sv, "monthly"sv},
		    {"365"sv, "yearly"sv},
		    {"7"sv, "weekly"sv},
		    {"annually"sv, "yearly"sv},
		    {"anually"sv, "yearly"sv},
		    {"bi-annually"sv, "semi-annually"sv},
		    {"biannually"sv, "semi-annually"sv},
		    {"boot"sv, "reboot"sv},
		    {"semiannually"sv, "semi-annually"sv},
		};
		if(auto itr = vore::binary_find(std::begin(replacements), std::end(replacements), this->period, key_or_plain); itr != std::end(replacements))
			this->period = itr->second;

		char buf[128];
		auto hour = this->start_hour;
		if(this->period == "reboot"sv) {
			this->boot_delay = std::max(this->boot_delay, static_cast<std::size_t>(1));
			this->schedule   = this->period;
			this->persistent = false;
		} else if(this->period == "minutely"sv) {
			this->schedule   = this->period;
			this->persistent = false;
		} else if(this->period == "hourly" && this->boot_delay == 0)
			this->schedule = "hourly"sv;
		else if(this->period == "hourly"sv) {
			this->schedule   = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "*-*-* *:%zu:0", this->boot_delay))};
			this->boot_delay = 0;
		} else if(this->period == "midnight" && this->boot_delay == 0)
			this->schedule = "daily"sv;
		else if(this->period == "midnight")
			this->schedule = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "*-*-* 0:%zu:0", this->boot_delay))};
		else if(std::binary_search(std::begin(TIME_UNITS_SET), std::end(TIME_UNITS_SET), this->period) && hour == 0 && this->boot_delay == 0)
			this->schedule = this->period;
		else if(this->period == "daily"sv)
			this->schedule = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "*-*-* %zu:%zu:0", hour, this->boot_delay))};
		else if(this->period == "weekly"sv)
			this->schedule = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "Mon *-*-* %zu:%zu:0", hour, this->boot_delay))};
		else if(this->period == "monthly"sv)
			this->schedule = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "*-*-1 %zu:%zu:0", hour, this->boot_delay))};
		else if(this->period == "quarterly"sv)
			this->schedule = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "*-1,4,7,10-1 %zu:%zu:0", hour, this->boot_delay))};
		else if(this->period == "semi-annually"sv)
			this->schedule = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "*-1,7-1 %zu:%zu:0", hour, this->boot_delay))};
		else if(this->period == "yearly"sv)
			this->schedule = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "*-1-1 %zu:%zu:0", hour, this->boot_delay))};
		else {
			bool err{};
			auto prd = int_map(this->period, err);
			if(err) {
				this->log(Log::ERR, "unknown schedule");
				this->schedule = this->period;
				return;
			}

			if(prd > 31) {
				// workaround for anacrontab
				std::size_t divisor = std::round(static_cast<float>(prd) / 30);
				this->schedule      = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "*-1/%zu-1 %zu:%zu:0", divisor, hour, this->boot_delay))};
			} else
				this->schedule = {buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "*-*-1/%zu %zu:%zu:0", prd, hour, this->boot_delay))};
		}
	}

	auto generate_schedule() -> void {
		if(!this->period.empty())
			this->generate_schedule_from_period();
		else
			this->generate_schedule_from_timespec();
	}

	auto generate_schedule_from_timespec() -> void {
		std::string dows;
		if(this->timespec_dow.size() != 1 || *std::begin(this->timespec_dow) != "*"sv) {  // != ['*']
			for(auto && dow : vore::span{std::begin(DOWS_SET) + this->sunday_is_seven, std::end(DOWS_SET) - !this->sunday_is_seven}) {
				if(this->timespec_dow.find(dow) == std::end(this->timespec_dow))
					continue;
				if(!dows.empty())
					dows += ',';
				dows += dow;
			}
			dows += ' ';
		}

		this->timespec_month.erase(0);
		this->timespec_dom.erase(0);

		if(this->timespec_month.empty() || this->timespec_dom.empty() || this->timespec_hour.empty() || this->timespec_minute.empty()) {
			this->valid = false;
			this->log(Log::ERR, "unknown schedule");
			return;
		}

		// %s*-%s-%s %s:%s:00
		this->schedule = std::move(dows);
		this->schedule += "*-"sv;
		char buf[3 + 1];  // 255
#define TIMESPEC_COMMA(field)                                                                                                \
	{                                                                                                                          \
		auto first = true;                                                                                                       \
		for(auto f : this->field) {                                                                                              \
			if(!std::exchange(first, false))                                                                                       \
				this->schedule += ',';                                                                                               \
			if(f == TIMESPEC_ASTERISK)                                                                                             \
				this->schedule += '*';                                                                                               \
			else                                                                                                                   \
				this->schedule += std::string_view{buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "%" PRIu8 "", f))}; \
		}                                                                                                                        \
	}
		TIMESPEC_COMMA(timespec_month);
		this->schedule += '-';
		TIMESPEC_COMMA(timespec_dom);
		this->schedule += ' ';
		TIMESPEC_COMMA(timespec_hour);
		this->schedule += ':';
		TIMESPEC_COMMA(timespec_minute);
		this->schedule += ":00"sv;
	}

	auto generate_scriptlet() -> std::optional<std::string> {
		// ...only if needed
		assert(!this->unit_name.empty());
		if(this->command.size() == 1) {
			struct stat sb;
			if(!stat(MAYBE_DUPA(this->command[0]), &sb) && S_ISREG(sb.st_mode)) {
				this->execstart = this->command[0];
				return {};
			}
		}

		auto scriptlet  = ((std::string{TARGET_DIR} += '/') += this->unit_name) += ".sh"sv;
		this->execstart = (std::string{this->shell} += ' ') += scriptlet;
		return std::move(scriptlet);
	}

	auto generate_unit_header(FILE * into, const char * tp, const char * inject) -> void {  // TODO: remove inject, just write it in caller; need for byte compat
		std::fputs("[Unit]\n", into);
		std::fprintf(into, "Description=[%s] \"", tp);
		for(auto desc = this->line; !desc.empty();) {
			auto pcent = desc.find('%');

			auto before = desc.substr(0, pcent);
			std::fwrite(before.data(), 1, before.size(), into);

			if(pcent != std::string_view::npos)
				desc.remove_prefix(pcent);
			else
				desc = {};
			while(!desc.empty() && desc[0] == '%') {
				std::fputs("%%", into);
				desc.remove_prefix(1);
			}
		}
		std::fputs("\"\n", into);
		std::fputs("Documentation=man:systemd-crontab-generator(8)\n", into);
		if(inject)
			std::fputs(inject, into);
		if(this->filename != "-"sv)
			std::fprintf(into, "SourcePath=%.*s\n", FORMAT_SV(this->filename));
	}

	auto generate_service(FILE * into) -> void {
		this->generate_unit_header(into, "Cron", nullptr);
		if(auto itr = this->environment.find("MAILTO"sv); itr != std::end(this->environment) && itr->second.empty())
			;  // mails explicitely disabled
		else if(!HAS_SENDMAIL)
			;  // mails automaticaly disabled
		else
			std::fputs("OnFailure=cron-failure@%i.service\n", into);
		if(this->user != "root"sv || this->filename.find(STATEDIR) != std::string_view::npos) {
			std::fputs("Requires=systemd-user-sessions.service\n", into);
			if(this->home)
				std::fprintf(into, "RequiresMountsFor=%.*s\n", FORMAT_SV(*this->home));
		}
		std::fputc('\n', into);

		std::fputs("[Service]\n", into);
		std::fputs("Type=oneshot\n", into);
		std::fputs("IgnoreSIGPIPE=false\n", into);
		std::fputs("KillMode=process\n", into);
		if(USE_LOGLEVELMAX != "no"sv)
			std::fprintf(into, "LogLevelMax=%.*s\n", FORMAT_SV(USE_LOGLEVELMAX));
		if(!this->schedule.empty() && this->boot_delay)
			if(!UPTIME || this->boot_delay > *UPTIME)
				std::fprintf(into, "ExecStartPre=-%.*s %zu\n", FORMAT_SV(BOOT_DELAY), this->boot_delay);
		std::fprintf(into, "ExecStart=%.*s\n", FORMAT_SV(this->execstart));
		if(this->environment.size()) {
			std::fputs("Environment=", into);
			environment_write(this->environment, into);
			std::fputc('\n', into);
		}
		std::fprintf(into, "User=%.*s\n", FORMAT_SV(this->user));
		if(this->batch) {
			std::fputs("CPUSchedulingPolicy=idle\n", into);
			std::fputs("IOSchedulingClass=idle\n", into);
		}
	}

	auto generate_timer(FILE * into) -> void {
		this->generate_unit_header(into, "Timer", "PartOf=cron.target\n");
		// std::fputs("PartOf=cron.target\n", into);
		if(this->testremoved)
			std::fprintf(into, "ConditionFileIsExecutable=%.*s\n", FORMAT_SV(*this->testremoved));
		std::fputc('\n', into);

		std::fputs("[Timer]\n", into);
		if(this->schedule == "reboot"sv)
			std::fprintf(into, "OnBootSec=%zum\n", this->boot_delay);
		else
			std::fprintf(into, "OnCalendar=%.*s\n", FORMAT_SV(this->schedule));
		if(this->random_delay > 1)
			std::fprintf(into, "RandomizedDelaySec=%zum\n", this->random_delay);
		if(this->persistent)
			std::fputs("Persistent=true\n", into);
	}

	auto generate_unit_name(std::uint64_t & seq) -> void {
		assert(!this->jobid.empty());
		this->unit_name = ("cron-"s += this->jobid) += '-';
		if(!this->persistent) {
			char buf[20 + 1];  // 18446744073709551615
			this->unit_name += std::string_view{buf, static_cast<std::size_t>(std::snprintf(buf, sizeof(buf), "%" PRIu64 "", seq++))};
		} else {
			// TODO: unit_id = hashlib.md5();
			// TODO: unit_id.update(bytes('\0'.join([this->schedule] + this->command), 'utf-8'));  // rember about '  ' -> ' ' sus
			// TODO:     unit_id = unit_id.hexdigest();
			//  self.unit_name = "cron-%s-%s" % (self.jobid, unit_id)
		}
	}

	// write the result in TARGET_DIR
	auto output() -> void {
#define OUTPUT_ERR(f, op)                                                               \
	{                                                                                     \
		char buf[512];                                                                      \
		snprintf(buf, sizeof(buf), "%.*s: %s: %s", FORMAT_SV(f), op, std::strerror(errno)); \
		this->log(Log::ERR, buf);                                                           \
		return;                                                                             \
	}
		assert(!this->unit_name.empty());

		if(auto scriptlet = this->generate_scriptlet()) {  // as a side-effect also changes this->execstart
			vore::file::FILE<false> f{scriptlet->c_str(), "we"};
			if(!f)
				OUTPUT_ERR(*scriptlet, "create");
			auto first = true;
			for(auto && hunk : this->command) {
				if(hunk.empty())
					continue;
				if(!std::exchange(first, false))
					std::fputc(' ', f);
				std::fwrite(hunk.data(), 1, hunk.size(), f);
			}
			if(!first)
				std::fputc('\n', f);
			if(std::ferror(f) || std::fflush(f))
				OUTPUT_ERR(*scriptlet, "write");
		}

		auto timer = ((std::string{TARGET_DIR} += '/') += this->unit_name) += ".timer"sv;
		{
			vore::file::FILE<false> t{timer.c_str(), "we"};
			if(!t)
				OUTPUT_ERR(timer, "create");
			this->generate_timer(t);
			if(std::ferror(t) || std::fflush(t))
				OUTPUT_ERR(timer, "write");
		}
		// TODO: dirfd for timers_dir and target_dir instead of string shit

		if(symlink(timer.c_str(), (((std::string{TIMERS_DIR} += '/') += this->unit_name) += ".timer"sv).c_str()) == -1 && errno != EEXIST)
			OUTPUT_ERR(timer, "link");

		auto service = ((std::string{TARGET_DIR} += '/') += this->unit_name) += ".service"sv;
		{
			vore::file::FILE<false> s{service.c_str(), "we"};
			if(!s)
				OUTPUT_ERR(service, "create");
			this->generate_service(s);
			if(std::ferror(s) || std::fflush(s))
				OUTPUT_ERR(service, "write");
		}
	}
};


template <class F>
static auto for_each_file(const char * dirname, F && cbk) -> void {
	if(vore::file::DIR dir{dirname}) {
		auto fd = dirfd(dir);
		struct stat sb;
		for(auto && ent : dir) {
			if(ent.d_type == DT_REG || (!fstatat(fd, ent.d_name, &sb, 0) && S_ISREG(sb.st_mode)))
				cbk(ent.d_name);
		}
	}
}

static auto environment_write(const std::map<std::string_view, std::string_view> & env, FILE * into) -> void {
	auto first = true;
	for(auto && [k, v] : env) {
		if(!std::exchange(first, false))
			std::fputc(' ', into);
		auto quote = v.find(' ') != std::string::npos;
		if(quote)
			std::fputc('"', into);
		std::fwrite(k.data(), 1, k.size(), into);
		std::fputc('=', into);
		std::fwrite(v.data(), 1, v.size(), into);
		if(quote)
			std::fputc('"', into);
	}
}

// parser shared with /usr/bin/crontab
template <class F>
static auto parse_crontab(std::string_view filename, bool withuser, bool monotonic, F && cbk) -> bool {
	vore::file::mapping map;
	{
		vore::file::fd<true> f{filename.data(), O_RDONLY | O_CLOEXEC};
		if(f == -1)
			return errno == ENOENT;

		struct stat sb;
		fstat(f, &sb);

		map = {nullptr, static_cast<std::size_t>(sb.st_size), PROT_READ, MAP_PRIVATE, f, 0};
		if(!map)
			return false;
	}

	std::map<std::string_view, std::string_view> environment;
	for(auto && line : vore::soft_tokenise{map, "\n"sv}) {
		while(!line.empty() && std::isspace(line[0]))
			line.remove_prefix(1);
		if(line.empty() || line[0] == '#')
			continue;
		while(!line.empty() && std::isspace(line.back()))
			line.remove_suffix(1);

		regmatch_t matches[3] = {{.rm_so = 0, .rm_eo = static_cast<regoff_t>(line.size())}};
		if(!regexec(&ENVVAR_RE, line.data(), sizeof(matches) / sizeof(*matches), matches, REG_STARTEND)) {
			auto key   = line.substr(matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);
			auto value = line.substr(matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
			while(!value.empty() && value[0] == '\'')
				value.remove_prefix(1);
			while(!value.empty() && value.back() == '\'')
				value.remove_suffix(1);
			while(!value.empty() && value[0] == '\"')
				value.remove_prefix(1);
			while(!value.empty() && value.back() == '\"')
				value.remove_suffix(1);
			while(!value.empty() && value[0] == ' ')
				value.remove_prefix(1);
			while(!value.empty() && value.back() == ' ')
				value.remove_suffix(1);
			environment[key] = value;
			continue;
		}

		Job j{filename, line};
		if(monotonic) {
			j.decode_environment(environment, /*default_persistent=*/true);
			j.parse_anacrontab();
		} else if(line[0] == '@') {
			j.decode_environment(environment, /*default_persistent=*/true);
			j.parse_crontab_at(withuser);
		} else {
			j.decode_environment(environment, /*default_persistent=*/false);
			j.parse_crontab_timespec(withuser);
		}
		j.decode();
		j.generate_schedule();
		cbk(j);
	}
	return true;
}
/*with open(filename, 'rb') as f:
    for rawline in f.readlines():
        rawline = rawline.strip()
        if not rawline or rawline.startswith(b'#'):
            continue

        #try:  # TODO: NOTE: this damages the line potentially
        #    line = rawline.decode('utf8')
        #except UnicodeDecodeError:
        #    # let's hope it's in a trailing comment
        #    try:
        #        line = rawline.split(b'#')[0].decode('utf8')
        #    except UnicodeDecodeError:
        #        line = rawline.decode('ascii', 'replace')

        #while '  ' in line:  # TODO: NOTE: disabled
        #    line = line.replace('  ', ' ')

        envvar = ENVVAR_RE.match(line)
        if envvar:
            key = envvar.group(1)
            # value = envvar.group(2)
            # value = value.strip("'").strip('"').strip(' ')
            environment[key] = value
            continue*/

static auto int_map(const std::string_view & str, bool & err) -> std::size_t {
	std::size_t ret = -1;
	if(!vore::parse_uint<10>(MAYBE_DUPA(str), ret))
		err = true;
	return ret;
}

static auto month_map(const std::string_view & month, bool & err) -> std::size_t {
	static const constexpr std::string_view months[] = {"jan"sv, "feb"sv, "mar"sv, "apr"sv, "may"sv, "jun"sv,
	                                                    "jul"sv, "aug"sv, "sep"sv, "oct"sv, "nov"sv, "dec"sv};
	if(auto ret = int_map(month, err); !err)
		return ret;
	else {
		auto mon = month.substr(0, 3);
		char buf[3];
		std::transform(std::begin(mon), std::end(mon), buf, ::tolower);
		if(auto itr = std::find(std::begin(months), std::end(months), std::string_view{buf, mon.size()}); itr != std::end(months))
			return (itr - std::begin(months)) + 1;
		else {
			err = true;
			return 0;
		}
	}
}

static auto dow_map(const std::string_view & dow_full, bool & err) -> std::size_t {
	static const constexpr std::string_view dows[] = {"sun"sv, "mon"sv, "tue"sv, "wed"sv, "thu"sv, "fri"sv, "sat"sv};
	auto dow                                       = dow_full.substr(0, 3);
	char buf[3];
	std::transform(std::begin(dow), std::end(dow), buf, ::tolower);
	if(auto itr = std::find(std::begin(dows), std::end(dows), std::string_view{buf, dow.size()}); itr != std::end(dows))
		return itr - std::begin(dows);
	else {
		return int_map(dow_full, err);
	}
}

template <class T, class V>
static auto parse_period(const std::string_view & value, const V & values, std::set<T> & into, std::size_t (*mapping)(const std::string_view &, bool &),
                         std::size_t base) -> bool {
	std::string_view range = value;
	std::size_t step       = 1;
	bool err{};
	if(auto idx = value.find('/'); idx != std::string_view::npos) {
		range     = value.substr(0, idx);
		auto rest = value.substr(idx + 1);
		if(rest.find('/') != std::string_view::npos)
			return false;
		step = int_map(rest, err);
		if(err)
			return false;
	}

	if(range == "*"sv) {
		for(std::size_t i = 0; i < std::distance(std::begin(values), std::end(values)); i += step)
			into.emplace(values[i]);
		return true;
	}


	auto start = range, end = range;
	if(auto idx = range.find('-'); idx != std::string_view::npos) {
		start = range.substr(0, idx);
		end   = range.substr(idx + 1);
		if(end.find('-') != std::string_view::npos)
			return false;
	}


	auto i_start = mapping(start, err) - 1 + !base;
	auto i_end   = std::min(mapping(end, err) + !base, static_cast<std::size_t>(std::distance(std::begin(values), std::end(values))));
	for(std::size_t i = i_start; i < i_end; i += step)
		into.emplace(values[i]);
	return true;
}

static auto generate_timer_unit(Job & job) -> void {
	static std::map<std::string, std::uint64_t> seqs;
	if(job.valid && job.is_active()) {
		job.generate_unit_name(seqs[job.jobid]);
		job.output();
	}
}

// schedule rerun of generators after /var is mounted
static auto workaround_var_not_mounted() -> bool {  // TODO: good error reporting
	if(vore::file::FILE<false> f{(std::string{TARGET_DIR} += "/cron-after-var.service"sv).c_str(), "we"}) {
		std::fputs("[Unit]\n"
		           "Description=Rerun systemd-crontab-generator because /var is a separate mount\n"
		           "Documentation=man:systemd.cron(7)\n"
		           "After=cron.target\n"
		           "ConditionDirectoryNotEmpty=" STATEDIR "\n"
		           "\n[Service]\n"
		           "Type=oneshot\n"
		           "ExecStart=/bin/sh -c \"systemctl daemon-reload ; systemctl try-restart cron.target\"\n",
		           f);

		if(std::ferror(f) || std::fflush(f))
			return false;
	} else
		return false;

	auto MULTIUSER_DIR = std::string{TARGET_DIR} += "/multi-user.target.wants"sv;
	// try://TODO
	//    os.makedirs(MULTIUSER_DIR)
	// except OSError as e:
	//    if e.errno != errno.EEXIST:
	//        raise

	if(symlink((std::string{TARGET_DIR} += "/cron-after-var.service"sv).c_str(), (MULTIUSER_DIR += "/cron-after-var.service"sv).c_str()) && errno != EEXIST)
		return false;
	return true;
}

// check if distribution also provide a native .timer
static auto is_masked(const char * path, std::string_view name, vore::span<const std::pair<std::string_view, std::string_view> *> distro_mapping) -> bool {
	auto unit_file = ("/___/systemd/system/"s += name) += ".timer";
	for(auto root : {"lib", "etc", "run"}) {
		std::memcpy(unit_file.data() + 1, root, 3);

		if(!access(unit_file.c_str(), F_OK)) {
			const char * reason = "native timer is present";
			char real[PATH_MAX];
			if(realpath(unit_file.c_str(), real) && real == "/dev/null"sv)
				// TODO: check 0-byte file
				reason = "it is masked";
			log(Log::NOTICE, "ignoring %s/%.*s because %s", path, FORMAT_SV(name), reason);
			return true;
		}
	}

	auto mapped_name = name;
	if(auto itr = vore::binary_find(std::begin(distro_mapping), std::end(distro_mapping), name, key_or_plain); itr != std::end(distro_mapping))
		mapped_name = itr->second;
	auto name_distro = std::string{mapped_name} += ".timer"sv;
	if(!access(("/lib/systemd/system/"s += name_distro).c_str(), F_OK)) {
		log(Log::NOTICE, "ignoring %s/%.*s because there is %.*s", path, FORMAT_SV(name), FORMAT_SV(name_distro));
		return true;
	}

	return false;
}

static auto is_backup(const std::string_view & name) -> bool {
	return name[0] == '.' || name.find('~') != std::string_view::npos || name.find(".dpkg-"sv) != std::string_view::npos;
}

static auto realmain() -> int {
	// try: // TODO
	//     os.makedirs(TIMERS_DIR, exist_ok=True)
	// except OSError as e:
	//     if e.errno != errno.EEXIST:
	//         raise

	std::optional<std::string> fallback_mailto;

	if(!parse_crontab("/etc/crontab", /*withuser=*/true, /*monotonic=*/false, [&](auto && job) {
		   if(auto itr = job.environment.find("MAILTO"sv); itr != std::end(job.environment))
			   fallback_mailto = itr->second;
		   if(!job.valid) {
			   log(Log::ERR, "truncated line in /etc/crontab: %.*s", FORMAT_SV(job.line));
			   return;
		   }
		   // legacy boilerplate
		   if(job.line.find("/etc/cron.hourly"sv) != std::string_view::npos ||  //
		      job.line.find("/etc/cron.daily"sv) != std::string_view::npos ||   //
		      job.line.find("/etc/cron.weekly"sv) != std::string_view::npos ||  //
		      job.line.find("/etc/cron.monthly"sv) != std::string_view::npos)
			   return;
		   generate_timer_unit(job);
	   })) {
		// TODO: log errno
	}

	for_each_file("/etc/cron.d", [&](std::string_view basename) {
		if(is_masked("/etc/cron.d", basename, {std::begin(CROND2TIMER), std::end(CROND2TIMER)}))
			return;
		if(is_backup(basename)) {
			log(Log::DEBUG, "ignoring %s/%.*s", "/etc/cron.d", FORMAT_SV(basename));
			return;
		}
		auto filename = "/etc/cron.d/"s += basename;
		if(!parse_crontab(filename, /*withuser=*/true, /*monotonic=*/false, [&](auto && job) {
			   if(!job.valid) {
				   log(Log::ERR, "truncated line in %.*s: %.*s", FORMAT_SV(filename), FORMAT_SV(job.line));
				   return;
			   }
			   if(fallback_mailto && job.environment.find("MAILTO"sv) == std::end(job.environment))
				   job.environment.emplace("MAILTO"sv, *fallback_mailto);
			   generate_timer_unit(job);
		   })) {
			// TODO: log errno
		}
	});

	if(!USE_RUNPARTS) {
		auto i = 0u;
		for(auto period : {"hourly", "daily", "weekly", "monthly", "yearly"}) {
			++i;
			auto directory = "/etc/cron."s += period;
			if(struct stat sb; stat(directory.c_str(), &sb) || !S_ISDIR(sb.st_mode))
				continue;
			for_each_file(directory.c_str(), [&](std::string_view basename) {
				if(is_masked(directory.c_str(), basename, {std::begin(PART2TIMER), std::end(PART2TIMER)}))
					return;
				if(is_backup(basename) || basename == "0anacron"sv) {
					log(Log::DEBUG, "ignoring %.*s/%.*s", FORMAT_SV(directory), FORMAT_SV(basename));
					return;
				}
				auto filename            = (directory + '/') += basename;
				std::string_view command = filename;
				Job job{filename, filename};
				job.persistent = true;
				job.period     = period;
				job.boot_delay = i * 5;
				job.command    = {{&command, &command + 1}, {}};
				job.jobid      = (std::string{period} += '-') += basename;
				job.decode();  // ensure clean jobid
				job.generate_schedule();
				if(fallback_mailto && job.environment.find("MAILTO"sv) == std::end(job.environment))
					job.environment.emplace("MAILTO"sv, *fallback_mailto);
				job.unit_name = "cron-" + job.jobid;
				job.output();
			});
		}

		if(!parse_crontab("/etc/anacrontab", /*withuser=*/false, /*monotonic=*/true, [&](auto && job) {
			   if(!job.valid) {
				   log(Log::ERR, "truncated line in /etc/anacrontab: %.*s", FORMAT_SV(job.line));
				   return;
			   }
			   generate_timer_unit(job);
		   })) {
			// TODO: log errno
		}

		if(struct stat sb; !stat(STATEDIR, &sb) || S_ISDIR(sb.st_mode)) {
			// /var is avaible
			for_each_file(STATEDIR, [&](std::string_view basename) {
				if(basename.find('.') != std::string_view::npos)
					return;

				auto filename = (std::string{STATEDIR} += '/') += basename;
				if(!parse_crontab(filename, /*withuser=*/false, /*monotonic=*/false, [&](auto && job) { generate_timer_unit(job); })) {
					// TODO: log errno
				}
			});
			vore::file::fd<false>{REBOOT_FILE, O_WRONLY | O_CREAT | O_CLOEXEC};
		} else {
			if(!workaround_var_not_mounted())
				// TODO: log errno
				;
		}
	}

	return 0;
}


int main(int argc, const char * const * argv) {
	std::setlocale(LC_ALL, "C.UTF-8");
	if(argc == 1) {
		std::fprintf(stderr, "usage: %s destination_folder\n", argv[0]);
		return 1;
	}

	SELF       = vore::basename(std::string_view{argv[0]}).data();
	TARGET_DIR = argv[1];
	TIMERS_DIR = std::string{argv[1]} += "/cron.target.wants"sv;

	RUN_BY_SYSTEMD = argc == 4;
	if(RUN_BY_SYSTEMD)
		if(vore::file::FILE<false> up{"/proc/uptime", "re"})
			if(std::fscanf(up, "%" SCNu64 "", &UPTIME.emplace()) != 1)
				UPTIME = {};

	return realmain();
}
