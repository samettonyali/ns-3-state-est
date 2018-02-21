using namespace std;

struct coordinates {
	double X;
	double Y;
};

template <typename T, int N> char (&array(T(&)[N]))[N];
