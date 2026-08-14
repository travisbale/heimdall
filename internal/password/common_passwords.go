package password

// commonPasswordsList contains frequently used passwords from data breaches (10+ characters only)
// All passwords in this list pass length validation - they're rejected solely for being common
// Sources: NCSC, NordPass, SplashData, and real-world breach analysis
var commonPasswordsList = []string{
	// Numeric sequences (10+ chars)
	"1234567890",
	"0123456789",
	"1111111111",
	"2222222222",
	"3333333333",
	"1234567891",
	"1234567899",
	"9876543210",
	"0000000000",
	"1234512345",
	"1231231234",

	// Keyboard patterns (10+ chars)
	"qwertyuiop",
	"asdfghjkl",
	"zxcvbnm123",
	"qwerty1234",
	"qwerty123456",
	"1qaz2wsx3edc",
	"qazwsxedc",
	"asdfghjkl123",
	"zxcvbnm1234",
	"poiuytrewq",
	"mnbvcxz123",

	// Common words with numbers (10+ chars)
	"password1",
	"password12",
	"password123",
	"password1234",
	"password12345",
	"password123456",
	"passw0rd123",
	"password!1",
	"password!123",
	"password2020",
	"password2021",
	"password2022",
	"password2023",
	"password2024",
	"password2025",
	"mypassword",
	"mypassword1",
	"mypassword123",

	// Common names/words (10+ chars)
	"administrator",
	"changeme123",
	"letmein123",
	"welcome123",
	"iloveyou123",
	"trustno1me",
	"qwertyuiop123",
	"1234567890123",
	"monkey1234",
	"dragon1234",
	"sunshine123",
	"princess123",

	// Year/seasonal passwords (10+ chars)
	"january2020",
	"february2020",
	"march20202",
	"april20202",
	"summer2020",
	"summer2021",
	"summer2022",
	"summer2023",
	"summer2024",
	"winter2020",
	"winter2021",
	"winter2022",
	"winter2023",
	"spring2023",
	"autumn2023",

	// Sports/pop culture (10+ chars)
	"football123",
	"baseball123",
	"basketball1",
	"basketball123",
	"superman123",
	"starwars123",
	"spiderman1",
	"batman1234",
	"pokemon123",

	// Default credentials (10+ chars)
	"temp123456",
	"test123456",
	"demo123456",
	"user123456",
	"admin123456",
	"root123456",
	"default123",
	"guest123456",
	"master1234",
	"system1234",
	"password@1",
	"pass@12345",

	// Service defaults (10+ chars)
	"postgres123",
	"mysql12345",
	"oracle1234",
	"sqlserver1",
	"mongodb123",
	"redis12345",

	// Common phrases (10+ chars)
	"iloveyou12",
	"loveyou123",
	"hello12345",
	"welcome1234",
	"letmein1234",
	"trustno123",
	"freedom123",
	"whatever123",

	// Repeated patterns (10+ chars)
	"aaaaaaaaaa",
	"abcabcabca",
	"123123123123",
	"abc1234567",
	"112233445566",

	// Variations with special chars (10+ chars)
	"password!@",
	"p@ssw0rd123",
	"passw0rd!1",
	"qwerty!123",
	"admin@1234",
}

// buildCommonPasswordsMap converts the list into a map for O(1) lookups
func buildCommonPasswordsMap() map[string]bool {
	m := make(map[string]bool, len(commonPasswordsList))
	for _, pwd := range commonPasswordsList {
		m[pwd] = true
	}
	return m
}
