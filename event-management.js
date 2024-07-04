$(document).ready(function() {
    // CSRF token setup for AJAX requests
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type)) {
                xhr.setRequestHeader("X-CSRFToken", $("meta[name='csrf-token']").attr("content"));
            }
        }
    });

    // Form validation
    function validateForm() {
        var isValid = true;
        $('#eventForm input, #eventForm textarea').each(function() {
            if (!this.checkValidity()) {
                isValid = false;
                $(this).addClass('is-invalid');
                $(this).siblings('.validation-message').addClass('active');
            } else {
                $(this).removeClass('is-invalid');
                $(this).siblings('.validation-message').removeClass('active');
            }
        });
        $('#submitBtn').attr('disabled', !isValid);
    }
    
    // Event listeners for form validation
    $('#eventForm input, #eventForm textarea').on('input', validateForm);
    validateForm();
    
    // Image preview function
    window.previewImage = function() {
        var file = document.getElementById('image_url').files[0];
        var reader = new FileReader();
        reader.onload = function (e) {
            $('#image_preview').attr('src', e.target.result).show();
        }
        reader.readAsDataURL(file);
    };

    // Populate cities based on state selection
    window.populateCities = function(stateName) {
        var stateCities = {
            "Andhra Pradesh": ["Visakhapatnam", "Vijayawada", "Amaravati", "Tirupati", "Kurnool"],
            "Arunachal Pradesh": ["Itanagar", "Naharlagun", "Pasighat", "Tawang", "Ziro"],
            "Assam": ["Guwahati", "Silchar", "Dibrugarh", "Jorhat", "Tezpur"],
            "Bihar": ["Patna", "Gaya", "Bhagalpur", "Muzaffarpur", "Darbhanga"],
            "Chhattisgarh": ["Raipur", "Bhilai", "Bilaspur", "Korba", "Durg"],
            "Goa": ["Panaji", "Margao", "Vasco da Gama", "Mapusa", "Ponda"],
            "Gujarat": ["Ahmedabad", "Surat", "Vadodara", "Rajkot", "Bhavnagar"],
            "Haryana": ["Faridabad", "Gurgaon", "Panipat", "Ambala", "Hisar"],
            "Himachal Pradesh": ["Shimla", "Mandi", "Dharamshala", "Kullu", "Manali"],
            "Jharkhand": ["Ranchi", "Jamshedpur", "Dhanbad", "Bokaro Steel City", "Hazaribagh"],
            "Karnataka": ["Bengaluru", "Mysuru", "Hubballi", "Mangalore", "Belagavi"],
            "Kerala": ["Thiruvananthapuram", "Kochi", "Kozhikode", "Thrissur", "Kollam"],
            "Madhya Pradesh": ["Bhopal", "Indore", "Jabalpur", "Gwalior", "Ujjain"],
            "Maharashtra": ["Mumbai", "Pune", "Nagpur", "Nashik", "Aurangabad"],
            "Manipur": ["Imphal", "Thoubal", "Bishnupur", "Churachandpur", "Kakching"],
            "Meghalaya": ["Shillong", "Tura", "Jowai", "Nongpoh", "Williamnagar"],
            "Mizoram": ["Aizawl", "Lunglei", "Saiha", "Champhai", "Serchhip"],
            "Nagaland": ["Kohima", "Dimapur", "Tuensang", "Mokokchung", "Wokha"],
            "Odisha": ["Bhubaneswar", "Cuttack", "Rourkela", "Berhampur", "Sambalpur"],
            "Punjab": ["Chandigarh", "Ludhiana", "Amritsar", "Jalandhar", "Patiala"],
            "Rajasthan": ["Jaipur", "Jodhpur", "Udaipur", "Kota", "Bikaner"],
            "Sikkim": ["Gangtok", "Namchi", "Gyalshing", "Mangan", "Singtam"],
            "Tamil Nadu": ["Chennai", "Coimbatore", "Madurai", "Tiruchirappalli", "Salem"],
            "Telangana": ["Hyderabad", "Warangal", "Karimnagar", "Nizamabad", "Khammam"],
            "Tripura": ["Agartala", "Udaipur", "Dharmanagar", "Ambassa", "Kailasahar"],
            "Uttar Pradesh": ["Lucknow", "Kanpur", "Varanasi", "Agra", "Meerut"],
            "Uttarakhand": ["Dehradun", "Haridwar", "Rishikesh", "Nainital", "Mussoorie"],
            "West Bengal": ["Kolkata", "Asansol", "Siliguri", "Durgapur", "Howrah"],
            "Andaman and Nicobar Islands": ["Port Blair", "Car Nicobar", "Mayabunder", "Bombooflat", "Garacharma"],
            "Chandigarh": ["Chandigarh"],
            "Dadra and Nagar Haveli and Daman and Diu": ["Daman", "Silvassa", "Diu", "Dadra", "Kavaratti"],
            "Lakshadweep": ["Kavaratti", "Minicoy", "Agatti", "Amini", "Andrott"],
            "Delhi": ["New Delhi", "North Delhi", "South Delhi", "East Delhi", "West Delhi"]
        };
        var cities = stateCities[stateName] || [];
        var citySelect = document.getElementById('city');
        citySelect.innerHTML = '<option value="">--- Select City ---</option>'; // Clear existing options
        cities.forEach(function(city) {
            var option = new Option(city, city);
            citySelect.options.add(option);
        });
    };
});
