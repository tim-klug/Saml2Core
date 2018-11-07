//MIT License

//Copyright (c) 2018 Dina Heidar

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
using System.Collections.Generic;

namespace SamlCore.AspNetCore.Authentication.Saml2
{
    /// <summary>
    /// 
    /// </summary>
    public class Saml2Endpoints
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2Endpoints"/> class.
        /// </summary>
        public Saml2Endpoints() { }
        /// <summary>
        /// Gets or sets the single sign on services.
        /// </summary>
        /// <value>
        /// The single sign on services.
        /// </value>
        public ICollection<LocationWithBinding> SingleSignOnServices { get; set; } =  new List<LocationWithBinding>();
        /// <summary>
        /// Gets or sets the single logout services.
        /// </summary>
        /// <value>
        /// The single logout services.
        /// </value>
        public ICollection<LocationWithBinding> SingleLogoutServices { get; set; } = new List<LocationWithBinding>();
        /// <summary>
        /// Gets or sets the name identifier formats.
        /// </summary>
        /// <value>
        /// The name identifier formats.
        /// </value>
        public ICollection<string> NameIDFormats { get; set; } = new List<string>();
    }
}